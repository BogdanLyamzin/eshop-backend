import {Router} from 'express';

import Cart from '../db/models/Cart.js';

const cartRouter = Router();

// Создать новую корзину
cartRouter.post('/', async (req, res) => {
  try {
    const cart = new Cart({ items: [] });
    await cart.save();
    res.status(201).json(cart);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка при создании корзины' });
  }
});

// Получить корзину по ID
cartRouter.get('/:cartId', async (req, res) => {
  try {
    // const cart = await Cart.findById(req.params.cartId).populate('items.productId');
    const cart = await Cart.findById(req.params.cartId);
    if (!cart) return res.status(404).json({ error: 'Корзина не найдена' });
    res.json(cart);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка при получении корзины' });
  }
});

// Добавить товар в корзину
cartRouter.post('/:cartId/items', async (req, res) => {
  const { productId, quantity } = req.body;

  try {
    const cart = await Cart.findById(req.params.cartId);
    if (!cart) return res.status(404).json({ error: 'Корзина не найдена' });

    const existingItem = cart.items.find(item => item.productId.equals(productId));
    if (existingItem) {
      existingItem.quantity += quantity || 1;
    } else {
      cart.items.push({ productId, quantity: quantity || 1 });
    }

    await cart.save();
    res.json(cart);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка при добавлении товара' });
  }
});

// Удалить товар из корзины
cartRouter.delete('/:cartId/items/:productId', async (req, res) => {
  try {
    const cart = await Cart.findById(req.params.cartId);
    if (!cart) return res.status(404).json({ error: 'Корзина не найдена' });

    cart.items = cart.items.filter(item => !item.productId.equals(req.params.productId));
    await cart.save();

    res.json(cart);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка при удалении товара' });
  }
});

// Очистить корзину
cartRouter.delete('/:cartId/items', async (req, res) => {
  try {
    const cart = await Cart.findById(req.params.cartId);
    if (!cart) return res.status(404).json({ error: 'Корзина не найдена' });

    cart.items = [];
    await cart.save();

    res.json(cart);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка при очистке корзины' });
  }
});

export default cartRouter;
