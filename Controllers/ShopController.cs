using Microsoft.AspNetCore.Mvc;
using sampleApi.Domain.Services;
using sampleApi.Domain.Model;
using Microsoft.AspNetCore.Authorization;

namespace sampleApi.Controllers
{
    
    [Route("api/[controller]")]
    [ApiController]
    public class ShopController : ControllerBase
    {
        private readonly IProduct _product;

        public ShopController(IProduct product)
        {
            _product = product;
        }

        [Authorize]
        [HttpGet]
        [Route("category/{categoryId:int?}")]
        public async Task<ActionResult<IEnumerable<Category>>> GetCategories(int? categoryId = null)
        {
            var categories = await _product.getCategory(categoryId);
            return Ok(categories);
        }

        [HttpGet]
        [Route("products/{categoryId:int}")]
        public async Task<ActionResult<IEnumerable<Category>>> GetProducts(int categoryId)
        {
            var products = await _product.getProducts(categoryId);
            return Ok(products);
        }

    }
}
