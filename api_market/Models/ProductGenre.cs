using System;
using System.Collections.Generic;

namespace api_market.Models
{
    public partial class ProductGenre
    {
        public int ProductGenreId { get; set; }
        public int GenreId { get; set; }
        public int ProductId { get; set; }

        public virtual Genre Genre { get; set; } = null!;
        public virtual Product Product { get; set; } = null!;
    }
}
