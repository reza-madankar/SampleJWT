using Microsoft.EntityFrameworkCore;
using sampleApi.Domain.Model;
using sampleApi.Domain.Services;

namespace sampleApi.Domain.Repository
{
    public class ProductRepository : IProduct
    {
        private readonly ShopContext _context;
        public ProductRepository(ShopContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<Category>> getCategory(int? id = null)
        {
            return await _context.Category
                .Where(x => x.superId == id)
                .ToListAsync();
        }

        public async Task<Product> getProductbyId(int id)
        {
            var product = await _context.Product
                .Where(x => x.id == id)
                .LastOrDefaultAsync();

            return product == null ? new Product() : product;
        }

        public async Task<IEnumerable<Product>> getProducts(int categoryId)
        {
            return await _context.Product
                 .Where(x => x.categoryId == categoryId)
                 .ToListAsync();
        }

        public async Task<bool> insetProduct(Product product)
        {
            await _context.Product.AddAsync(product);
            await _context.SaveChangesAsync();

            return true;
        }

        public async Task<bool> removeProduct(int id)
        {
            var product = await getProductbyId(id);

            if (product != null)
            {
                _context.Product.Remove(product);
                await _context.SaveChangesAsync();

                return true;
            }
            else
            {
                return false;
            }

        }

        public async Task<bool> updateProduct(int id, string name, decimal price)
        {
            var product = await getProductbyId(id);

            if (product != null)
            {
                product.name = name;
                product.price = price;

                await _context.SaveChangesAsync();

                return true;
            }
            else
            {
                return false;
            }
        }

    }
}
