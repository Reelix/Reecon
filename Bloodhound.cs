using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;

namespace Reecon
{
    public class Bloodhound
    {
        private static string BloodhoundUsername = "admin";
        private static string BloodhoundPassword = "Password111!";
        private static string BloodhoundURL = "http://localhost:8080/"; // With trailing /

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
                    GetInfo(username);
                }
            }
            else
            {
                Console.WriteLine($"Usage: {General.ProgramName} -bloodhound -ingest");
                Console.WriteLine($"Usage: {General.ProgramName} -bloodhound username@domain.com");
            }
        }

        public static void Ingest()
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

        public record Node(int Key, string Name, string ObjectId, string Type);

        public record Relationship(string Type, int FromKey, int ToKey);

        public static void GetInfo(string userId)
        {
            string? jwt = Auth();
            if (jwt == null)
            {
                Console.WriteLine("Error - Unable to auth :(");
                return;
            }

            Console.WriteLine("Exploring data...");
            // Get Profile ObjectId
            (string Text, HttpStatusCode StatusCode) profileIdReq = Web.DownloadString($"http://localhost:8080/api/v2/search?q={userId}", JWT: jwt);
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

            string profileId = JsonDocument.Parse(profileIdReq.Text).RootElement.GetProperty("data")[0].GetProperty("objectid").ToString();
            Console.WriteLine("PID: " + profileId);

            // Memberships
            (string Text, HttpStatusCode StatusCode) membershipsReq = Web.DownloadString($"http://localhost:8080/api/v2/users/{profileId}/memberships", JWT: jwt);
            var membershipsInfo = JsonDocument.Parse(membershipsReq.Text);
            JsonElement membershipsChildren = membershipsInfo.RootElement.GetProperty("data");
            foreach (JsonElement membership in membershipsChildren.EnumerateArray())
            {
                string membershipName = membership.GetProperty("name").GetString() ?? "INVALID - BUG REELIX";
                if (membershipName.StartsWith("REMOTE MANAGEMENT USERS")) // Any other super important ones?
                {
                    Console.WriteLine("Member Of: " +membershipName.Recolor(Color.Green) + " <---- WINRM!!!");
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

            (List<NodeItem> parsedNodes, List<RelationshipItem> parsedRelationships) = ParseJsonBlob(ownablesReq.Text);

            List<Node> nodeList = new List<Node>();
            List<Relationship> relationshipList = new List<Relationship>();


            // Console.WriteLine($"\nParsed Nodes: {parsedNodes.Count}");
            foreach (NodeItem node in parsedNodes)
            {
                // Console.WriteLine($"  Node Key: {node.OriginalKey}, Name: {node.Data?.Name} (ObjectId: {node.Data?.ObjectId}), Type: {node.Data?.NodeType}");
                Node thisNode = new Node(int.Parse(node.OriginalKey ?? "Break"), node.Data?.Name ?? "Unknown Name - Bug Reelix", node.Data?.ObjectId ?? "Unknown Id - Bug Reelix",
                    node.Data?.NodeType ?? "Unknown Type - Bug Reelix");
                nodeList.Add(thisNode);
            }

            // Console.WriteLine($"\nParsed Relationships: {parsedRelationships.Count}");
            foreach (RelationshipItem rel in parsedRelationships)
            {
                // Console.WriteLine($"  Rel Key: {rel.OriginalKey}, Type: {rel.LabelInfo?.Text}, From: {rel.Id1}, To: {rel.Id2}");
                Relationship thisRelationship = new Relationship(rel.LabelInfo?.Text ?? "", int.Parse(rel.Id1 ?? "Break"), int.Parse(rel.Id2 ?? "Break"));
                relationshipList.Add(thisRelationship);
            }


            Console.WriteLine();

            if (parsedNodes.Count == 0)
            {
                return;
            }

            var nodeMap = nodeList.ToDictionary(node => node.Key);
            var startNode = nodeMap.Values.FirstOrDefault(node => node.ObjectId == profileId);
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
                var outgoingRelationships = relationshipList.Where(rel => rel.FromKey == currentNode.Key);

                foreach (var rel in outgoingRelationships)
                {
                    // Find the target node of the relationship
                    if (nodeMap.TryGetValue(rel.ToKey, out var targetNode))
                    {
                        // Print the relationship we found
                        Console.WriteLine($"{currentNode.Name} ({currentNode.Type}) -> {rel.Type} -> {targetNode.Name} ({targetNode.Type})");
                        GetNodeInfo(currentNode.Name, currentNode.Type, rel.Type, targetNode.Name, targetNode.Type);

                        // If we haven't processed this target node before, add it to the queue
                        // to process its relationships in a future iteration.
                        if (!processedNodeKeys.Contains(targetNode.Key))
                        {
                            processedNodeKeys.Add(targetNode.Key);
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

            // The Computer has AddSelf to a Group
            if (node1Type == "Computer" && relationshipType == "AddSelf" && node2Type == "Group")
            {
                string domain = node2Name.Split('@')[1];
                string computerName = node1Name.Replace('.' + domain, "") + "$"; // Computer names with commands end with a $
                string groupName = node2Name.Split('@')[0];
                Console.WriteLine($"- The Computer {computerName} can add itself to the Group {groupName}");
                Console.WriteLine(
                    $"-- bloodyAD -k --host {"dc".Recolor(Color.Green)}.{domain} -d {domain} -u '{computerName}' -p '{"COMPUTER-PASSWORD".Recolor(Color.Green)}' add groupMember {groupName} '{computerName}'");
            }

            // The Group has ForceChangePassword to a User
            if (node1Type == "Group" && relationshipType == "ForceChangePassword" && node2Type == "User")
            {
                string groupName = node1Name.Split('@')[0];
                string domain = node1Name.Split('@')[1];
                string userName = node2Name.Split('@')[0];
                Console.WriteLine($"- Members of {groupName} can change the password of {userName}");
                Console.WriteLine(
                    $"-- bloodyAD -k --host {"dc".Recolor(Color.Green)}.{domain} -d {domain} -u '{"OWNED-USER".Recolor(Color.Green)}' -p '{"OWNED-USER_PASSWORD".Recolor(Color.Green)}' set password {userName} 'Password123!'");
            }
            
            // The User has WriteSPN to another User
            if (node1Type == "User" && relationshipType == "WriteSPN" && node2Type == "User")
            {
                string ourUserName = node1Name.Split('@')[0];
                string userDomain = node1Name.Split('@')[1];
                string otherUserName = node2Name.Split('@')[0];
                Console.WriteLine($"- The User {ourUserName} can set the SPN of {otherUserName} and grab the hash to crack");
                Console.WriteLine($"-- bloodyAD --host {"dc".Recolor(Color.Green)}.{userDomain} -d {userDomain} -u {ourUserName} -p '{"PASSWORD".Recolor(Color.Green)}' set object {otherUserName} serviceprincipalname -v 'reelix/{otherUserName}'");
                Console.WriteLine($"-- GetUserSPNs.py -dc-ip {"IP".Recolor(Color.Green)} '{userDomain}/{ourUserName}:{"PASSWORD".Recolor(Color.Green)}' -request -k -dc-host {"dc".Recolor(Color.Green)}.{userDomain}");
                Console.WriteLine("-- KRB_AP_ERR_SKEW(Clock skew too great) -> faketime");
            }

            /*
            // The Computer can ForceChangePassword of a User
            if (sortedNodes.Count == 2 && sortedRelationships.Count == 1)
            {
                if (sortedNodes[0].Data?.NodeType == "Computer" &&
                    sortedNodes[1].Data?.NodeType == "User" &&
                    sortedRelationships[0].LabelInfo?.Text == "ForceChangePassword")
                {
                    NodeItem computerNode = sortedNodes[0];
                    NodeItem userNode = sortedNodes[1];
                    string? computerName = computerNode.Data?.Name?.Split('@')[0];
                    string? userName = userNode.Data?.Name?.Split('@')[0];
                    string? domain = userNode.Data?.Name?.Split('@')[1];
                    Console.WriteLine("- Interesting Thing Found!");
                    Console.WriteLine($"- {computerName} can change the password of {userName} without knowing it!");
                    Console.WriteLine(
                        $"-- net rpc password '{userName}' 'Password123!' -U '{domain}'/'{computerName}'%'{"PASSWORD_OR_HASH".Recolor(Color.Green)}' -S '{domain}' --pw-nt-hash (If applicable)");
                }
            }

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
                    Console.WriteLine($"-- python3 gMSADumper.py -u '{"UserInGroup".Recolor(Color.Green)}' -p '{"UserPass".Recolor(Color.Green)}' -d '{domain}'");
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
                    Console.WriteLine($"-- python3 targetedKerberoast.py -v -d '{domain}' -u '{originUser}' -p '{"PASSWORD_HERE".Recolor(Color.Green)}'");
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
                    Console.WriteLine($"- {userDomain} can add themself to {groupName} due to AddSelf permissions.");
                    Console.WriteLine(
                        $"-- bloodyAD --host {"IP".Recolor(Color.Green)} -d {userDomain} -u {userName} -p '{"PASSWORD".Recolor(Color.Green)}' add groupMember {groupName} {userName}");
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
                    $"-- rpcclient -U '{username}'%'{"PASSWORD".Recolor(Color.Green)}' {"IP_HERE".Recolor(Color.Green)} -c 'setuserinfo {otherUsername} 23 Password123!'");
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
                        $"-- Check if user is a member of the group: net rpc group members '{groupName}' -U '{username}'%'{"PASSWORD".Recolor(Color.Green)}' -S '{userDomain}'");
                    Console.WriteLine(
                        $"-- Add user to group: net rpc group addmem '{groupName}' '{username}' -U '{username}'%'{"PASSWORD".Recolor(Color.Green)}' -S '{userDomain}'");
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
                        $"-- Check if user is a member of the group: net rpc group members '{groupName}' -U '{username}'%'{"PASSWORD".Recolor(Color.Green)}' -S '{userDomain}'");
                    Console.WriteLine(
                        $"-- Add user to group: net rpc group addmem '{groupName}' '{username}' -U '{username}'%'{"PASSWORD".Recolor(Color.Green)}' -S '{userDomain}'");
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
                            Console.WriteLine($"- certipy shadow auto -u '{"USERNAME".Recolor(Color.Green)}' -p '{"PASSWORD".Recolor(Color.Green)}' -dc-ip IP -account '{username}'");
                            Console.WriteLine($" -- certipy find -u '{username}' -hashes {"HASH_FROM_ABOVE".Recolor(Color.Green)} -dc-ip IP_HERE -text -vulnerable -stdout");
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
            Web.UploadDataResult authResult = Web.UploadData($"{BloodhoundURL}api/v2/login", PostContent: byteData, ContentHeaders: headers);
            if (authResult.StatusCode == null)
            {
                Console.WriteLine($"No HTTP Status Code - Is the server at {BloodhoundURL} down?");
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
            Dictionary<string, string> authHeader = new();
            authHeader.Add("Authorization", "Bearer " + jwt);
            byte[] emptyPost = new byte[1];
            Web.UploadDataResult fileUploadJob = Web.UploadData($"http://localhost:8080/api/v2/file-upload/start",
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
            Web.UploadDataResult zipUpload = Web.UploadData($"http://localhost:8080/api/v2/file-upload/{jobId}",
                RequestHeaders: authHeader, ContentHeaders: zipHeader, PostContent: fileBytes);

            if (zipUpload.StatusCode != HttpStatusCode.Accepted)
            {
                Console.WriteLine("File Upload Failed.");
                return false;
            }

            // Start the Job processing
            Web.UploadDataResult fileUploadComplete = Web.UploadData(
                $"http://localhost:8080/api/v2/file-upload/{jobId}/end",
                RequestHeaders: authHeader, PostContent: emptyPost);

            if (fileUploadComplete.StatusCode != HttpStatusCode.OK)
            {
                // Pushed
                Console.WriteLine("File Upload Finalize Failed :(");
                return false;
            }

            // Watch the ingesting process until it's completed

            // Due to a bug with the API
            // https://github.com/SpecterOps/BloodHound/issues/1505
            // This is far more complicated than it should be.
            Console.WriteLine($"File Upload finalized with Job ID: {jobId}");
            Console.WriteLine("Data needs to be ingested - This may take awhile.");
            DateTime beforeData = DateTime.Now;
            Console.Write("Ingesting...");

            string statusMessage = "";
            while (statusMessage != "Complete")
            {
                string jobData = Web.DownloadString("http://localhost:8080/api/v2/file-upload?id=" + jobId.ToString(),
                    JWT: jwt).Text;
                JsonElement.ArrayEnumerator dataArray =
                    JsonDocument.Parse(jobData).RootElement.GetProperty("data").EnumerateArray();
                foreach (JsonElement dataItem in dataArray)
                {
                    if (dataItem.GetProperty("id").GetInt32() == jobId)
                    {
                        statusMessage = dataItem.GetProperty("status_message").GetString() ?? string.Empty;
                        Console.Write(".");
                        break;
                    }
                }

                Thread.Sleep(2500);
            }

            DateTime afterData = DateTime.Now;
            TimeSpan ingestTime = afterData - beforeData;
            Console.WriteLine();
            Console.WriteLine($"Upload ingested in {ingestTime.TotalSeconds} seconds.");
            return true;
        }

        private static (List<NodeItem> Nodes, List<RelationshipItem> Relationships) ParseJsonBlob(string jsonBlob)
        {
            List<NodeItem> nodes = [];
            List<RelationshipItem> relationships = [];

            // Get the default instance of the source-generated context.
            BloodhoundJsonContext context = BloodhoundJsonContext.Default;

            // Parse the entire JSON into a JsonDocument
            using (JsonDocument document = JsonDocument.Parse(jsonBlob))
            {
                JsonElement root = document.RootElement;

                // Iterate over each property in the root object
                foreach (JsonProperty property in root.EnumerateObject())
                {
                    string key = property.Name;
                    JsonElement valueElement = property.Value;

                    if (int.TryParse(key, out _)) // Check if the key is purely numeric (node)
                    {
                        try
                        {
                            // Use the context for deserialization
                            NodeItem? node = valueElement.Deserialize(context.NodeItem);
                            if (node != null)
                            {
                                node.OriginalKey = key; // Store the original key
                                nodes.Add(node);
                            }
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
                            // Use the context for deserialization
                            RelationshipItem? rel = valueElement.Deserialize(context.RelationshipItem);
                            if (rel != null)
                            {
                                rel.OriginalKey = key; // Store the original key
                                relationships.Add(rel);
                            }
                        }
                        catch (JsonException ex)
                        {
                            Console.WriteLine($"Error deserializing relationship with key '{key}': {ex.Message}");
                        }
                    }
                    else
                    {
                        // You might want to log or handle other top-level keys if they are expected
                        // For example, BloodHound JSON can have a "meta" key or "nodes"/"edges" at the root
                        // depending on the API endpoint or export format.
                        // The current logic assumes a flat structure of numerically-keyed nodes
                        // and "rel_"-prefixed relationships directly under the root object.
                        // Console.WriteLine($"Skipping unrecognized top-level key: {key}");
                    }
                }
            }

            return (nodes, relationships);
        }
    }

    // Define the JSON context with source generation
    [JsonSourceGenerationOptions(WriteIndented = true, PropertyNameCaseInsensitive = true)]
    [JsonSerializable(typeof(NodeDataItem))]
    [JsonSerializable(typeof(NodeBorder))]
    [JsonSerializable(typeof(NodeFontIcon))]
    [JsonSerializable(typeof(NodeLabel))]
    [JsonSerializable(typeof(NodeItem))]
    [JsonSerializable(typeof(RelationshipEnd2))]
    [JsonSerializable(typeof(RelationshipLabel))]
    [JsonSerializable(typeof(RelationshipItem))]
    public partial class BloodhoundJsonContext : JsonSerializerContext
    {
    }

    //
    // Nodes
    //
    public class NodeDataItem
    {
        [JsonPropertyName("name")] public string? Name { get; set; }

        [JsonPropertyName("nodetype")] public string? NodeType { get; set; }

        [JsonPropertyName("objectid")] public string? ObjectId { get; set; }

        [JsonPropertyName("system_tags")] public string? SystemTags { get; set; } // Can be null or a string like "owned"
    }

    public class NodeBorder
    {
        [JsonPropertyName("color")] public string? Color { get; set; }
    }

    public class NodeFontIcon
    {
        [JsonPropertyName("text")] public string? Text { get; set; }
    }

    public class NodeLabel
    {
        [JsonPropertyName("backgroundColor")] public string? BackgroundColor { get; set; }

        [JsonPropertyName("center")] public bool Center { get; set; }

        [JsonPropertyName("fontSize")] public int FontSize { get; set; }

        [JsonPropertyName("text")] public string? Text { get; set; }
    }

    public class NodeItem
    {
        // We can add the original key if needed, e.g., "17", "20"
        [JsonIgnore] // This property is not part of the JSON value itself
        public string? OriginalKey { get; set; }

        [JsonPropertyName("color")] public string? Color { get; set; }

        [JsonPropertyName("data")] public NodeDataItem? Data { get; set; }

        [JsonPropertyName("border")] public NodeBorder? Border { get; set; }

        [JsonPropertyName("fontIcon")] public NodeFontIcon? FontIcon { get; set; }

        [JsonPropertyName("label")] public NodeLabel? LabelInfo { get; set; } // Renamed to avoid conflict if a property was just 'Label'

        [JsonPropertyName("size")] public int Size { get; set; }
    }

    //
    // Relationships
    // 
    public class RelationshipEnd2
    {
        [JsonPropertyName("arrow")] public bool Arrow { get; set; }
    }

    public class RelationshipLabel
    {
        [JsonPropertyName("text")] public string? Text { get; set; }
    }

    public class RelationshipItem
    {
        // We can add the original key if needed, e.g., "rel_104"
        [JsonIgnore] public string? OriginalKey { get; set; }

        [JsonPropertyName("color")] public string? Color { get; set; }

        [JsonPropertyName("end2")] public RelationshipEnd2? End2 { get; set; }

        [JsonPropertyName("id1")] public string? Id1 { get; set; }

        [JsonPropertyName("id2")] public string? Id2 { get; set; }

        [JsonPropertyName("label")] public RelationshipLabel? LabelInfo { get; set; } // Renamed
    }
}