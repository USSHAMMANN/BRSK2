using System;
using System.Collections.Generic;

namespace mvc_app.Models
{
    public partial class User
    {
        public int UserId { get; set; }
        public string UserLogin { get; set; } = null!;
        public string UserPassword { get; set; } = null!;
        public string? UserName { get; set; }
        public string UserEmail { get; set; } = null!;
        public int? UserRole { get; set; }
        public bool? UserStatus { get; set; }

        public virtual Role? UserRoleNavigation { get; set; }
    }
}
