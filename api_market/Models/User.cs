using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace api_market.Models
{
    public partial class User
    {
        public User()
        {
            Orders = new HashSet<Order>();
        }

        public int UserId { get; set; }
        public string UserLogin { get; set; } = null!;
        [JsonIgnore]
        public string UserPassword { get; set; } = null!;
        public string? UserName { get; set; }
        public string UserEmail { get; set; } = null!;
        public int? UserRole { get; set; }
        public bool? UserStatus { get; set; }

        public virtual Role? UserRoleNavigation { get; set; }
        [JsonIgnore]
        public virtual ICollection<Order> Orders { get; set; }
    }
}
