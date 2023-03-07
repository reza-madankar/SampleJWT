using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace sampleApi.Domain.Model
{
    public class Category
    {
        public Category()
        {
            subs = new HashSet<Category>();
            products = new HashSet<Product>();
        }


        [Key]
        public int id { get; set; }

        [MaxLength(500), Required]
        public string title { get; set; }

        public int index { get; set; }

        [MaxLength(500)]
        public string tagCode { get; set; }

        public int? superId { get; set; }



        [ForeignKey("superId")]
        public virtual Category super { get; set; }
        public virtual ICollection<Category> subs { get; set; }
        public virtual ICollection<Product> products { get; set; }

    }
}