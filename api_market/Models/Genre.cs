using System;
using System.Collections.Generic;

namespace api_market.Models
{
    public partial class Genre
    {
        public Genre()
        {
            ProductGenres = new HashSet<ProductGenre>();
        }

        public int GenreId { get; set; }
        public string GenreName { get; set; } = null!;

        public virtual ICollection<ProductGenre> ProductGenres { get; set; }
    }
}
