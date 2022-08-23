using HashingSaltingMVCExample.Models;
using HashingSaltingMVCExample.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace HashingSaltingMVCExample.Controllers
{
    public class IdentityController : Controller
    {
        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel loginViewModel, string? returnUrl = null)
        {
            if (!ModelState.IsValid) return View(loginViewModel);

            Tuple<string, string> tuple = Crypto.HashPassword("H3110w0r1d!");
            string pass = tuple.Item1;
            string salt = tuple.Item2;

            LoginViewModel user = new LoginViewModel()
            {
                Email = "xyz@example.com",
                Password = pass,
            };

            if (loginViewModel == null)
            {
                ModelState.AddModelError("IncorrectData", "Provided login data is incorrect. Please try again.");
                return View(loginViewModel);
            }

            if (loginViewModel.Email != user.Email)
            {
                ModelState.AddModelError("IncorrectData", "Provided login data is incorrect. Please try again.");
                return View(loginViewModel);
            }

            string hashedPass = Crypto.HashPassword(loginViewModel.Password, salt).Item1;
            
            if(hashedPass != user.Password)
            {
                ModelState.AddModelError("IncorrectData", "Provided login data is incorrect. Please try again.");
                return View(loginViewModel);
            }

            try
            {
                // Security context for Identity
                List<Claim> claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, "1"),
                    new Claim(ClaimTypes.Name, "Victor Pérez Asuaje"),
                    new Claim(ClaimTypes.Email, loginViewModel.Email),
                };

                ClaimsIdentity identity = new ClaimsIdentity(claims, "AuthCookie");

                // Container for the security context
                ClaimsPrincipal principal = new ClaimsPrincipal(identity);

                // Encryption and serialization in a cookie for simplicity
                await HttpContext.SignInAsync("AuthCookie", principal);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("AuthError", "An error ocurred during authentication");
                return View();
            }
 
            return RedirectToAction(actionName: "Index", controllerName: "Home");
        }

    }
}
