import createHttpError from "http-errors";
import jwt from "jsonwebtoken";

import { findUser } from "../services/auth.js";

export const authenticate = async(req, res, next)=> {
    // const {authorization} = req.headers;
    const authorization = req.get("Authorization");
    if(!authorization) {
        return next(createHttpError(401, "Authorization header missing"));
    }
    const [bearer, token] = authorization.split(" ");
    if(bearer !== "Bearer") {
        return next(createHttpError(401, "Header must have type Bearer"));
    }
    try {
        const {email} = jwt.verify(token, process.env.JWT_SECRET);
        const user = await findUser({email});
        if(!user || !user.token) {
            return next(createHttpError(401, "User not found"));
        }
        
        req.user = user;

        next();
    }
    catch(error) {
        next(createHttpError(401, error.message));
    }
};