import mongoose from 'mongoose';

const cartItemSchema = new mongoose.Schema({
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product',
    required: true,
  },
  quantity: {
    type: Number,
    required: true,
    default: 1,
    min: 1,
  },
});

const cartSchema = new mongoose.Schema({
  items: [cartItemSchema],
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model('Cart', cartSchema);
