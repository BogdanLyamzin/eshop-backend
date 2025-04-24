import createHttpError from 'http-errors';

import { getProducts, getProductById } from '../services/products.js';

export const getProductsController = async (req, res) => {
 
  const data = await getProducts();

  res.json({
    status: 200,
    message: 'Successfully find products',
    data,
  });
};

export const getProductByIdController = async (req, res) => {
  const { id } = req.params;

  const data = await getProductById(id);

  if (!data) {
    throw createHttpError(404, `Product with id=${id} not found`);
  }

  res.json({
    status: 200,
    message: `Successfully find product with id=${id}`,
    data,
  });
};

