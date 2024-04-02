using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace api_market.Models
{
    public partial class Role
    {
        public Role()
        {
            Users = new HashSet<User>();
        }

        public int RoleId { get; set; }
        public string? RoleName { get; set; }

        [JsonIgnore]

        public virtual ICollection<User> Users { get; set; }
    }
}
