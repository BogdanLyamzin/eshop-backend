import ProductCollection from '../db/models/Movie.js';


export const getProducts = async () => ProductCollection.find();

export const getProductById = (id) => ProductCollection.findOne({ _id: id });
