import { Router } from 'express';

import { ctrlWrapper } from '../utils/ctrlWrapper.js';

import {
  getMoviesController,
  getMovieByIdController,
  addMovieController,
  upsertMovieController,
  patchMovieController,
  deleteMovieController,
  getMovieTypesController,
} from '../controllers/movies.js';

import { isValidId } from '../middlewares/isValidId.js';
import {authenticate} from "../middlewares/authenticate.js";

import { validateBody } from '../utils/validateBody.js';

import { movieAddSchema, movieUpdateSchema } from '../validation/movies.js';

const moviesRouter = Router();

moviesRouter.use(authenticate);

moviesRouter.get('/', ctrlWrapper(getMoviesController));

moviesRouter.get('/:id', isValidId, ctrlWrapper(getMovieByIdController));

moviesRouter.post('/', validateBody(movieAddSchema), ctrlWrapper(addMovieController));

moviesRouter.put('/:id', isValidId, validateBody(movieAddSchema), ctrlWrapper(upsertMovieController));

moviesRouter.patch('/:id', isValidId, validateBody(movieUpdateSchema), ctrlWrapper(patchMovieController));

moviesRouter.delete('/:id', isValidId, ctrlWrapper(deleteMovieController));

moviesRouter.get("/types/all", ctrlWrapper(getMovieTypesController));

export default moviesRouter;
