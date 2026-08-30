using System;
using System.Drawing;
using System.Net;
using System.Text.Json;

namespace Reecon;

public class Osint_GitHub
{
    public class GitHubInfo
    {
        public bool Exists = false;
        public string Info = "";
    }
    
    public static GitHubInfo GetInfo(string username)
    {
        GitHubInfo gitHubInfo = new GitHubInfo();
        Web.HttpInfo httpProfileInfo = Web.GetHttpInfo($"https://api.github.com/users/{username}");
        if (httpProfileInfo.StatusCode != HttpStatusCode.NotFound && httpProfileInfo.PageText != null)
        {
            gitHubInfo.Exists = true;
            string info = "";
            
            JsonDocument profileInfo = JsonDocument.Parse(httpProfileInfo.PageText);
            JsonElement login = profileInfo.RootElement.GetProperty("login");
            info += "-- Login: " + login + Environment.NewLine;
            JsonElement htmlLink = profileInfo.RootElement.GetProperty("html_url");
            info += $"-- Link: {htmlLink}" + Environment.NewLine;
            JsonElement name = profileInfo.RootElement.GetProperty("name");
            if (name.ValueKind != JsonValueKind.Null)
            {
                info += "-- Name: " + name + Environment.NewLine;
            }
            // Bio?
            JsonElement company = profileInfo.RootElement.GetProperty("company");
            if (company.ValueKind != JsonValueKind.Null)
            {
                info += "-- Company: " + company + Environment.NewLine;
            }
            JsonElement location = profileInfo.RootElement.GetProperty("location");
            if (location.ValueKind != JsonValueKind.Null)
            {
                info += "-- Location: " + location + Environment.NewLine;
            }
            JsonElement avatar = profileInfo.RootElement.GetProperty("avatar_url");
            if (avatar.ValueKind != JsonValueKind.Null)
            {
                info +=  "-- Avatar Picture: " + avatar + Environment.NewLine;
            }
            JsonElement createdAt = profileInfo.RootElement.GetProperty("created_at");
            info +=  $"-- Account Created At: {createdAt}" + Environment.NewLine;
            JsonElement blog = profileInfo.RootElement.GetProperty("blog");
            if (blog.ToString() != "")
            {
                info +=  "-- Blog: " + blog + Environment.NewLine;
            }
            
            // Check for self repo (Common for profiles)
            Web.HttpInfo selfHttpRepoInfo = Web.GetHttpInfo($"https://api.github.com/repos/{username}/{username}/commits");
            if (selfHttpRepoInfo.StatusCode != HttpStatusCode.NotFound && selfHttpRepoInfo.PageText != null)
            {
                JsonDocument selfRepoInfo = JsonDocument.Parse(selfHttpRepoInfo.PageText);
                JsonElement emailAddress = selfRepoInfo.RootElement[0].GetProperty("commit").GetProperty("author").GetProperty("email");
                info += "-- Self Repo Commit Email: " + emailAddress + Environment.NewLine;
            }
            // Get Repos
            // TODO: Parse Repos + Commits
            // Repos: https://api.github.com/users/sakurasnowangelaiko/repos
            // Commits (And everything else): https://api.github.com/users/sakurasnowangelaiko/events (
            gitHubInfo.Info = info.Trim(Environment.NewLine.ToCharArray());
        }

        return gitHubInfo;
    }
}