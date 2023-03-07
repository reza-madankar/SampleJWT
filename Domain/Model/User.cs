using System.ComponentModel.DataAnnotations;

namespace sampleApi.Domain.Model
{
    public class User
    {
        public User()
        {
            userRoles = new HashSet<UserRole>();
        }


        [Key]
        public int id { get; set; }

        [MaxLength(500), Required]
        public string name { get; set; }
        [MaxLength(500), Required]
        public string email { get; set; }
        [MaxLength(500), Required]
        public string password { get; set; }


        public virtual ICollection<UserRole> userRoles { get; set; }
    }
}
