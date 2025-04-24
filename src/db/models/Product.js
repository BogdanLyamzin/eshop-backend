import { Schema, model } from 'mongoose';

import { handleSaveError, setUpdateSettings } from './hooks.js';

const productSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
    },
    image: {
      type: String,
      required: true,
    },
    price: {
      type: Number,
      min: 0,
      required: true,
    },
    description: {
      type: String,
      required: true,
    },
  },
  { versionKey: false, timestamps: true },
);

productSchema.post('save', handleSaveError);

productSchema.pre('findOneAndUpdate', setUpdateSettings);

productSchema.post('findOneAndUpdate', handleSaveError);

const ProductCollection = model('product', productSchema);

export default ProductCollection;
