using api_market.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace api_market.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        db_marketContext dbContext = new db_marketContext();
        [HttpGet]
        [Authorize(Roles = "Системный администратор")]
        public async Task<ActionResult<List<User>>> GetUsers()
        {
            List<User> users = dbContext.Users.Include(x => x.UserRoleNavigation).ToList();
            if (users.Count == 0)
            {
                return NoContent();
            }
            return Ok(users);
        }
        [HttpGet]
        [Authorize(Roles = "Системный администратор")]

        [Route("{user_id}")]
        public async Task<ActionResult<List<User>>> GetUser(int user_id)
        {
            List<User> users = dbContext.Users.Include(x => x.UserRoleNavigation).ToList();

            User user = users.FirstOrDefault(x => x.UserId == user_id);
            if (user == null)
            {
                return NoContent();
            }
            return Ok(user);
        }
        [HttpGet]
        [Authorize(Roles = "Системный администратор")]
        [Route("byName/{username}")]
        public async Task<ActionResult<List<User>>> GetUsersByName(string username)
        {
            List<User> users = dbContext.Users.Include(x => x.UserRoleNavigation).Where(x => x.UserName.Contains(username)).ToList();
            if (users.Count == 0)
            {
                return NoContent();
            }
            return Ok(users);
        }
        [HttpPut]
        [Authorize(Roles = "Системный администратор")]
        [Route("{user_id}/DeactiveUser")]
        public async Task<ActionResult<List<User>>> DeactiveUser(int user_id)
        {
            User user = dbContext.Users.Find(user_id);

            if (user == null)
            {
                return BadRequest();
            }
            user.UserStatus = false;
            dbContext.Update(user);
            dbContext.SaveChanges();
            return Ok();
        }
        [HttpPut]
        [Route("{user_id}/ActiveUser")]
        [Authorize(Roles = "Системный администратор")]
        public async Task<ActionResult<List<User>>> ActiveUser(int user_id)
        {
            User user = dbContext.Users.Find(user_id);

            if (user == null)
            {
                return BadRequest();
            }
            user.UserStatus = true;
            dbContext.Update(user);
            dbContext.SaveChanges();
            return Ok();
        }

        [HttpPut]
        [Authorize(Roles = "Системный администратор")]
        [Route("SetAdminRole")]
        public async Task<ActionResult<List<User>>> SetAdminRole(int user_id)
        {
            User user = dbContext.Users.Find(user_id);

            if (user == null)
            {
                return BadRequest();
            }
            user.UserRole = 2;
            dbContext.Update(user);
            dbContext.SaveChanges();
            return Ok();
        }
        [HttpPut]
        [Authorize(Roles = "Системный администратор")]
        [Route("SetSysAdminRole")]
        public async Task<ActionResult<List<User>>> SetSysAdminRole(int user_id)
        {
            User user = dbContext.Users.Find(user_id);

            if (user == null)
            {
                return BadRequest();
            }
            user.UserRole = 3;
            dbContext.Update(user);
            dbContext.SaveChanges();
            return Ok();
        }
        [HttpPut]
        [Authorize(Roles = "Системный администратор")]
        [Route("SetClientRole")]
        public async Task<ActionResult<List<User>>> SetClientRole(int user_id)
        {
            User user = dbContext.Users.Find(user_id);

            if (user == null)
            {
                return BadRequest();
            }
            user.UserRole = 1;
            dbContext.Update(user);
            dbContext.SaveChanges();
            return Ok();
        }

        [HttpGet]
        [Authorize]
        [Route("CurrentUserInfo")]
        public User GetCurrectUserInfo()
        {
            return GetCurrectUser();
        }
        [NonAction]
        public User GetCurrectUser()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            if (identity != null)
            {
                var userClaims = identity.Claims;

                return new User
                {
                    UserId = Convert.ToInt32(userClaims.FirstOrDefault(o => o.Type == ClaimTypes.NameIdentifier)?.Value),
                    UserName = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Name)?.Value,
                };
            }
            return null;
        }
    }
}
