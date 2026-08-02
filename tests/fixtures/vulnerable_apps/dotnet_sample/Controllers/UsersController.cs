using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

[ApiController]
[Route("api/users")]
public sealed class UsersController : ControllerBase
{
    [HttpGet("search")]
    public async Task<IActionResult> Search(string name, SqlConnection connection)
    {
        var query = $"SELECT * FROM Users WHERE Name = '{name}'";
        await using var command = new SqlCommand(query, connection);
        await command.ExecuteReaderAsync();
        return Ok();
    }

    [HttpGet("safe-search")]
    public async Task<IActionResult> SafeSearch(string name, SqlConnection connection)
    {
        await using var command = new SqlCommand(
            "SELECT * FROM Users WHERE Name = @name", connection);
        command.Parameters.AddWithValue("@name", name);
        await command.ExecuteReaderAsync();
        return Ok();
    }
}
