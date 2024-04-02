using Microsoft.AspNetCore.Mvc;
using mvc_app.Models;
using Newtonsoft.Json;
using System.Net;
using System.Text;

namespace mvc_app.Api
{
    public class ApiOrder : Api
    {
        public ApiOrder(IHttpContextAccessor httpContextAccessor) : base(httpContextAccessor)
        {
        }

        public async Task<HttpStatusCode> Purchase(List<int> id_list)
        {
            var json = JsonConvert.SerializeObject(id_list);
            var data = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await client.PostAsync("Orders", data);
            current_status = response.StatusCode;
            return response.StatusCode;
        }

        public async Task<List<Order>> GetOrders()
        {
            List<Order> orders = new List<Order>(0);
            var response = await client.GetAsync("Orders");
            current_status = response.StatusCode;

            orders = JsonConvert.DeserializeObject<List<Order>>(response.Content.ReadAsStringAsync().Result);
            return orders;
        }
        public async Task<List<Order>> GetUserOrders(int user_id)
        {
            List<Order> orders = new List<Order>(0);

            var response = await client.GetAsync($"Orders/{user_id}");
            current_status = response.StatusCode;

            orders = JsonConvert.DeserializeObject<List<Order>>(response.Content.ReadAsStringAsync().Result);
            return orders;
        }
        public async Task<List<Order>> GetAllOrders()
        {
            List<Order> orders = new List<Order>(0);

            var response = await client.GetAsync($"Orders/UsersOrders");
            current_status = response.StatusCode;

            orders = JsonConvert.DeserializeObject<List<Order>>(response.Content.ReadAsStringAsync().Result);
            return orders;
        }
        public async Task<List<Order>> GetOrderByUserName(string userName)
        {
            List<Order> orders = new List<Order>(0);

            var response = await client.GetAsync($"Orders/UserOrdersByName/{userName}");
            current_status = response.StatusCode;

            orders = JsonConvert.DeserializeObject<List<Order>>(response.Content.ReadAsStringAsync().Result);
            return orders;
        }

    }
}
