using System.ComponentModel.DataAnnotations;

namespace MVC2_Auth.Models
{
    public class Register
    {
        [Required( ErrorMessage = "UserName is required")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
    }
}
