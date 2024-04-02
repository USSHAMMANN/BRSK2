using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace mvc_app.Api
{
    public class Cart
    {
        CookieManager cookieManager;
        public Cart(IHttpContextAccessor httpContextAccessor) 
        {
            cookieManager = new CookieManager(httpContextAccessor);
        }

        public void AddToCart(int product_id)
        {
            List<int> cart = GetCartList();

            if (cart.Contains(product_id))
            {
                return;
            }
            else
            {
                cart.Add(product_id);
            }
            SaveCart(cart);
        }
        public List<int> GetCartList()
        {
            List<int> cartList = new List<int>(0);
            string cartListJson = cookieManager.GetCookie("cart").Value;
            if (!cartListJson.IsNullOrEmpty())
            {
                cartList = JsonConvert.DeserializeObject<List<int>>(cartListJson);  
            }
            return cartList;
        }
        public void RemoveFromCart(int product_id)
        {
            List<int> cart = GetCartList();
            if (cart.Count == 0)
            {
                return;
            }
            else
            {
                cart.Remove(product_id);
                SaveCart(cart);
            }

        }
        public void SaveCart(List<int> cart)
        {
            string cartListJson = JsonConvert.SerializeObject(cart);
            cookieManager.RemoveCookie("cart");
            cookieManager.AddCookie("cart", cartListJson);
        }
        public void ClearCart()
        {
            cookieManager.RemoveCookie("cart");
        }
    }
}
