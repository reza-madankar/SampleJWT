using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using sampleApi.Domain.Model;
using sampleApi.Domain.Services;
using sampleApi.Model;
using sampleApi.Security;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace sampleApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly IUser _user;

        public AuthController(IConfiguration configuration, IUser user)
        {
            _configuration = configuration;
            _user = user;
        }

        [HttpGet]
        [Route("role")]
        public async Task<ActionResult<IEnumerable<Role>>> GetRoles()
        {
            var roles = await _user.getRoles();
            return Ok(roles);
        }

        [HttpGet]
        [Route("users/{roleId:int}")]
        public async Task<ActionResult<IEnumerable<Category>>> GetUsers(int roleId)
        {
            var users = await _user.getUsers(roleId);
            return Ok(users);
        }

        [HttpPost("login")]
        public async Task<ActionResult<User>> Login(UserDto userDto)
        {
            var user = await _user.getUser(userDto.Username);

            if (user == null)
            {
                return NotFound("Not Found.");
            }

            string passKey = _configuration.GetSection("Encrypt:PassKey").Value;
            var passEncrypt = StringCipher.Encrypt(userDto.Password, passKey);

            if (user.password != passEncrypt)
            {
                return NotFound("Password incorrect.");
            }

            string token = CreateToken(user);

            return Ok(new { user, token });
        }
 
        private string CreateToken(User user)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            var passKey = _configuration.GetSection("Encrypt:Token").Value;
            var tokenKey = Encoding.ASCII.GetBytes(passKey);

            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.email)
                }),
                //set duration of token here
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(tokenKey),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

    }
}
