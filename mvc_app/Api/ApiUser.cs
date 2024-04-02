using mvc_app.Models;
using Newtonsoft.Json;
using System.Net;
using System.Text;

namespace mvc_app.Api
{
    public class ApiUser : Api
    {
        public ApiUser(IHttpContextAccessor httpContextAccessor) : base(httpContextAccessor)
        {

        }

        public async Task<List<User>> GetUsers()
        {
            List<User> users = new List<User>();
            var response = await client.GetAsync($"Users");
            current_status = response.StatusCode;
            if (response.StatusCode == HttpStatusCode.OK)
            {
                users = JsonConvert.DeserializeObject<List<User>>(response.Content.ReadAsStringAsync().Result);
            }

            return users;
        }

        public async Task<User> GetUser(int user_id)
        {
            User user = new User();
            var response = await client.GetAsync($"Users/{user_id}");
            current_status = response.StatusCode;
            if (response.StatusCode == HttpStatusCode.OK)
            {
                user = JsonConvert.DeserializeObject<User>(response.Content.ReadAsStringAsync().Result);
            }

            return user;
        }

        public async Task<List<User>> GetUsersByName(string name)
        {
            List<User> users = new List<User>();
            var response = await client.GetAsync($"Users/byName/{name}");
            current_status = response.StatusCode;
            if (response.StatusCode == HttpStatusCode.OK)
            {
                users = JsonConvert.DeserializeObject<List<User>>(response.Content.ReadAsStringAsync().Result);
            }

            return users;
        }

        public async Task SetAdminRole(int user_id)
        {
            var response = await client.PutAsync($"Users/SetAdminRole?user_id={user_id}", null);
            return;
        }
        public async Task SetSysAdminRole(int user_id)
        {
            var response = await client.PutAsync($"Users/SetSysAdminRole?user_id={user_id}", null);
            return;
        }
        public async Task SetClientRole(int user_id)
        {
            var response = await client.PutAsync($"Users/SetClientRole?user_id={user_id}", null);
            return;
        }
    }
}
