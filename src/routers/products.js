import { Router } from 'express';

import { ctrlWrapper } from '../utils/ctrlWrapper.js';

import {
  getProductsController,
  getProductByIdController,
} from '../controllers/products.js';

import { isValidId } from '../middlewares/isValidId.js';

const moviesRouter = Router();

moviesRouter.get('/', ctrlWrapper(getProductsController));

moviesRouter.get('/:id', isValidId, ctrlWrapper(getProductByIdController));

export default moviesRouter;
