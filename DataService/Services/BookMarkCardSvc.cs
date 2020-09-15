using DataService.Interfaces;
using Microsoft.AspNetCore.Identity;
using ModelService;
using Serilog;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace DataService.Services
{
    public class BookMarkCardSvc :IBookmarkCardSvc
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private string[] UserRoles = new[] { "Administrator", "User" };
        private readonly ApplicationDbContext _db;
        public BookMarkCardSvc(UserManager<ApplicationUser> userManager,
            ApplicationDbContext db)
        {
            _userManager = userManager;
            _db = db;
        }
        public async Task<bool> CreateBookMarkCard(BookmarkCard bookmarkCard)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(bookmarkCard.UserName);
                bookmarkCard.IsAdmin = user.isAdmin;
                bookmarkCard.IsCardValidationRequired = user.isAdmin; //if admin card needs no validation, if user then it needs validation
                bookmarkCard.IsCardExpired = false;
                await _db.BookMarkCards.AddAsync(bookmarkCard);
                // persist changes in the DB
                await _db.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                Log.Error("An error occurred while saving the new bookmark card  {Error} {StackTrace} {InnerException} {Source}",
                    ex.Message, ex.StackTrace, ex.InnerException, ex.Source);
            }
            return false;
        }
    }
}
