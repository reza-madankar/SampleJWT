using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace sampleApi.Domain.Model
{
    public class UserRole
    {
   
        [Key]
        public int id { get; set; }
        public int userId { get; set; }
        public int roleId { get; set; }


        [ForeignKey("roleId")]
        public virtual Role role { get; set; }

        [ForeignKey("userId")]
        public virtual User user { get; set; }
    }
}
