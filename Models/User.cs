using MongoDB.Bson;

namespace ZenGChatApi.Models;

public class User
{
    public string Id { get; set; } = ObjectId.GenerateNewId().ToString();
    public string Email { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Bio { get; set; } = "ZenG Enthusiast";
}