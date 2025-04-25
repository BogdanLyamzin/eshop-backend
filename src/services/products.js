import ProductыCollection from '../db/models/Product.js';


export const getProducts = async () => ProductыCollection.find();

export const getProductById = (id) => ProductыCollection.findOne({ _id: id });
