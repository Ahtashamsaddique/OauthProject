using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace OauthWebApplicatoin.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class SecureController : ControllerBase
    {
        [HttpGet("public")]
        public IActionResult PublicEndpoint()
        {
            return Ok("This is a public endpoint.");
        }

        [Authorize(Policy = "ApiUser")]
        [HttpGet("private")]
        public IActionResult PrivateEndpoint()
        {
            return Ok("This is a protected endpoint.");
        }
    }
}
