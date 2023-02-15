using JwtAuth.Manager;
using JwtAuth.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuth
{
    class Program
    {
        private static JwtContainerModel GetJwtContainerModel(string name, string email)
        {
            return new JwtContainerModel()
            {
                Claims = new Claim[]
                {
                    new Claim(ClaimTypes.Name,name),
                    new Claim(ClaimTypes.Email, email)
                }
            };
        }
        static void Main(string[] args)
        {
            IAuthContainerModel model= GetJwtContainerModel("zin min","zinminaungzm.1998@gamil.com");
            IAuthService authService = new JwtService(model.SecretKey);
            string token = authService.GenerateToken(model);

            if (authService.IsValidToken(token))
            {
                Console.WriteLine(token);
            }

        }
    }
}
