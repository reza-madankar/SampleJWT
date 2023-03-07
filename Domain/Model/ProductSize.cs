using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace sampleApi.Domain.Model
{
    public class ProductSize
    {
        [Key]
        public int id { get; set; }

        [MaxLength(500), Required]
        public string filter { get; set; }

        [MaxLength(500), Required]
        public string code { get; set; }

        public int productId { get; set; }



        [ForeignKey("productId")]
        public virtual Product product { get; set; }
    }
}
