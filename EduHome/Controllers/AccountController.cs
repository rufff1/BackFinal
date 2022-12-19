
using EduHome.Model;
using EduHome.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EduHome.Controllers
{
    public class AccountController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        public AccountController(RoleManager<IdentityRole> roleManager, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)
        {
            _roleManager = roleManager;
            _signInManager = signInManager;
            _userManager = userManager;
        }



        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

       [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult>  Register(RegsterVM registerVM)
        {
            if (!ModelState.IsValid)
            {
                return View(registerVM);
            }

            AppUser appUser = new AppUser
            {
                Name = registerVM.Name,
                UserName = registerVM.UserName,
                Email = registerVM.Email
            };


            IdentityResult identityResult = await _userManager.CreateAsync(appUser, registerVM.Paswoord);
            if (!identityResult.Succeeded)
            {
                foreach (var item in identityResult.Errors)
                {
                    ModelState.AddModelError("", item.Description);
                }
                return View(registerVM);
            }
            await _userManager.AddToRoleAsync(appUser, "Member");
            
            return RedirectToAction("Index", "Home");
        }

           [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]

        public async Task<IActionResult> Login(LognVM loginVM)
        {
            if (!ModelState.IsValid)
            {
                return View(loginVM);
            }
            AppUser appUser = await _userManager.FindByNameAsync(loginVM.Username);
            if (appUser == null)
            {
                ModelState.AddModelError("", "Email ve ya Paswoord duzgun qeyd edin");
                return View(loginVM);
            }
            Microsoft.AspNetCore.Identity.SignInResult signInResult = await _signInManager.CheckPasswordSignInAsync(appUser, loginVM.Password, true);
            if (signInResult.IsLockedOut)
            {
                ModelState.AddModelError("", "Sifreni 3 defeden artig sehf yigdiginiz ucun bloklandiniz");
                return View(loginVM);
            }
            if (!signInResult.Succeeded)
            {
                ModelState.AddModelError("", "Email ve ya Paswoord duzgun qeyd edin");
                return View(loginVM);
            }
            await _signInManager.PasswordSignInAsync(appUser, loginVM.Password, loginVM.RememberMe, true);

            return RedirectToAction("Index", "Home");



        }

        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(Login));
        }


        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Profile( )
        {
            AppUser appUser = await _userManager.FindByNameAsync(User.Identity.Name);
            ProfleVM profileVM = new ProfleVM
            {
                Name = appUser.Name,
                UserName = appUser.UserName,
                Email = appUser.Email,
            };


            return View(profileVM);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public async Task<IActionResult> Profile(ProfleVM profileVM)
        {
            if (!ModelState.IsValid)
            {
                return View(profileVM);
            }
            bool check = false;

            AppUser appUser = await _userManager.FindByNameAsync(User.Identity.Name);
            if (appUser.Name.ToLowerInvariant() != profileVM.Name.Trim().ToLowerInvariant())
            {
                check = true;
                appUser.Name = profileVM.Name.Trim();

            }
            if (appUser.NormalizedUserName != profileVM.UserName.Trim().ToUpperInvariant())
            {
                check = true;
                appUser.UserName = profileVM.UserName.Trim();

            }
            if (appUser.NormalizedEmail != profileVM.Email.Trim().ToLowerInvariant())
            {
                check = true;
                appUser.Email = profileVM.Email.Trim();

            }
            if (check)
            {
                IdentityResult identityResult = await _userManager.UpdateAsync(appUser);
                if (!identityResult.Succeeded)
                {
                    foreach (var item in identityResult.Errors)
                    {
                        ModelState.AddModelError("", item.Description);
                    }
                    return View(profileVM);
                }
            }
            if (!string.IsNullOrWhiteSpace(profileVM.CurrentPaswoord))
            {
                if (!await _userManager.CheckPasswordAsync(appUser, profileVM.CurrentPaswoord))
                {
                    ModelState.AddModelError("CurrentPaswoord", "Sifrenizi duzgun daxil edin");
                    return View(profileVM);

                }
                if (profileVM.NewPaswoord == profileVM.CurrentPaswoord)
                {
                    ModelState.AddModelError("NewPaswoord", "Yeni Sifrenizle hal-hazirdaki eynidir");
                    return View(profileVM);

                }
                string token = await _userManager.GeneratePasswordResetTokenAsync(appUser);
                IdentityResult identityResult = await _userManager.ResetPasswordAsync(appUser, token, profileVM.NewPaswoord);
                if (!identityResult.Succeeded)
                {
                    foreach (var item in identityResult.Errors)
                    {
                        ModelState.AddModelError("", item.Description);
                    }
                    return View(profileVM);

                }
            }


            return RedirectToAction("Index", "Home");
        }
    }
}
