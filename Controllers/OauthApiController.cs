using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace OauthWebApplicatoin.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OauthApiController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public OauthApiController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpGet("signin-google")]
        public async Task<IActionResult> SignInGoogleCallback()
        {
            // Get the authentication result with tokens and claims
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            if (result?.Principal == null)
                return BadRequest("Error during authentication");

            // Extract the access token from the result
            var accessToken = result.Properties.Items[".Token.access_token"];

            // Send the token to the front-end
            return Redirect($"http://localhost:4200/auth/callback?token={accessToken}");
        }

        [AllowAnonymous]
        [HttpGet("google-login")]
        public IActionResult GoogleLogin()
        {
            var redirectUrl = Url.Action("GoogleResponse", "Auth");
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            return Challenge(properties, "Google");
        }

        [AllowAnonymous]
        [HttpGet("google-response")]
        public async Task<IActionResult> GoogleResponse()
        {
            var result = await HttpContext.AuthenticateAsync("Google");
            if (result?.Principal == null)
            {
                return BadRequest("Error logging in with Google.");
            }

            var claims = result.Principal.Identities
                .FirstOrDefault()?.Claims.Select(claim => new
                {
                    claim.Type,
                    claim.Value
                });

            return Ok(claims);
        }

        [AllowAnonymous]
        [HttpPost("token")]
        public IActionResult GenerateJwtToken()
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "test_user"),
                new Claim(JwtRegisteredClaimNames.Email, "user@example.com"),
                new Claim("scope", "api_access")
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpirationMinutes"])),
                signingCredentials: credentials);

            return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
        }
        [HttpPost("logout")]
        public IActionResult Logout()
        {
            // Remove the cookie by setting it with an expired timestamp
            Response.Cookies.Append("AuthToken", "", new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // Set to true if using HTTPS
                Expires = DateTimeOffset.UtcNow.AddDays(-1) // Set an expired date to remove the cookie
            });

            return Ok(new { message = "Logged out successfully" });
        }
    }
}

