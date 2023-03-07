using System.ComponentModel.DataAnnotations;

namespace sampleApi.Domain.Model
{
    public class Role
    {
        public Role()
        {
            userRoles = new HashSet<UserRole>();
        }


        [Key]
        public int id { get; set; }

        [MaxLength(500), Required]
        public string title { get; set; }


        public virtual ICollection<UserRole> userRoles { get; set; }
    }
}
