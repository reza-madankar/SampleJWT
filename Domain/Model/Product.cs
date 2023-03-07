using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace sampleApi.Domain.Model
{
    public class Product
    {
        public Product()
        {
            productSizes = new HashSet<ProductSize>();
        }


        [Key]
        public int id { get; set; }

        [MaxLength(500), Required]
        public string code { get; set; }

        [MaxLength(500), Required]
        public string name { get; set; }

        [MaxLength(500), Required]
        public string colors { get; set; }

        public decimal price { get; set; }

        [MaxLength(500), Required]
        public string image { get; set; }

        public int stock { get; set; }

        public bool comingSoon { get; set; }

        public int categoryId { get; set; }



        [ForeignKey("categoryId")]
        public virtual Category category { get; set; }
        public virtual ICollection<ProductSize> productSizes { get; set; }
    }
}
