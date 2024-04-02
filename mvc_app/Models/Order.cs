using System;
using System.Collections.Generic;

namespace mvc_app.Models
{
    public partial class Order
    {
        public int OrderId { get; set; }
        public DateTime OrderDate { get; set; }
        public int UserId { get; set; }

        public virtual User User { get; set; } = null!;
        public virtual ICollection<OrderList> OrderLists { get; set; }
    }
}
