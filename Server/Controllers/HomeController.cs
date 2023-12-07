using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Server.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

    [Authorize]
    public IActionResult Secret()
    {
        return View();
    }

    public IActionResult Authenticate()
    {
        var claims = new []
        {
            new Claim(JwtRegisteredClaimNames.Sub, "some_id"),   
            new Claim("Granny","Cookie")   
        };

        var secretBytes = Encoding.UTF8.GetBytes(SecretConstants.Secret);
        var key = new SymmetricSecurityKey(secretBytes);
        var algorithm = SecurityAlgorithms.HmacSha256;

        var signInCredentials = new SigningCredentials(key, algorithm);

        /// C# representation of Json Token
        var token = new JwtSecurityToken(
            SecretConstants.Issuer,
            SecretConstants.Audiance,
            claims,
            notBefore: DateTime.Now,
            expires: DateTime.Now.AddHours(5),
            signInCredentials
        );

        var tokenJson = new JwtSecurityTokenHandler().WriteToken(token);

        return Ok(new { access_token = tokenJson });
        // return Ok(new { access_token = tokenJson, secretBytes = secretBytes, key = key, algorithm = algorithm , signInCredentials = signInCredentials, token = token });
    }

    /// Decoding a Token part passed by Url
    public IActionResult DecodeToken(String part)
    {
        if(!string.IsNullOrEmpty(part))
        {
            var bytes = Convert.FromBase64String(part);
            return Ok(Encoding.UTF8.GetString(bytes));
        }
        return BadRequest("No part received");
    }
}