import bcrypt from "bcrypt";
import createHttpError from "http-errors";

import jwt from "jsonwebtoken";

import UserCollection from "../db/models/User.js";

export const findUser = query => UserCollection.findOne(query);

export const registerUser = async payload => {
    const {email, password} = payload;
    const user = await findUser({email});

    if(user) {
        throw createHttpError(409, "Email already in use");
    }

    const hashPassword = await bcrypt.hash(password, 10);
    
    return await UserCollection.create({...payload, password: hashPassword});
};

export const loginUser = async payload => {
    const {email, password} = payload;
    const user = await findUser({email});
    if(!user) {
        throw createHttpError(401, "Email or password invalid");
    }

    const passwordCompare = await bcrypt.compare(password, user.password);
    if(!passwordCompare) {
        throw createHttpError(401, "Email or password invalid");
    }

    const token = jwt.sign({email}, process.env.JWT_SECRET, {expiresIn: "24h"});

    await UserCollection.findOneAndUpdate({email}, {token});

    return {token};
};

export const refreshUser = async ({refreshToken, sessionId})=> {
   
};

export const logoutUser = ({email}) => UserCollection.findOneAndUpdate({email}, {token: null});