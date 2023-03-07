using sampleApi.Domain.Model;

namespace sampleApi.Domain.Services
{
    public interface IProduct
    {
        Task<IEnumerable<Category>> getCategory(int? id = null);

        Task<IEnumerable<Product>> getProducts(int categoryId);

        Task<Product> getProductbyId(int id);

        Task<bool> insetProduct(Product product);

        Task<bool> updateProduct(int id, string name, decimal price);

        Task<bool> removeProduct(int id);

    }
}
