using System;
using System.Collections.Generic;

namespace api_market.Models
{
    public partial class Order
    {
        public Order()
        {
            OrderLists = new HashSet<OrderList>();
        }

        public int OrderId { get; set; }
        public DateTime OrderDate { get; set; }
        public int UserId { get; set; }

        public virtual User User { get; set; } = null!;
        public virtual ICollection<OrderList> OrderLists { get; set; }
    }
}
