import bcrypt from "bcrypt";
import createHttpError from "http-errors";
import {randomBytes} from "node:crypto";
import jwt from "jsonwebtoken";

import UserCollection from "../db/models/User.js";
import SessionCollection from '../db/models/Session.js';

import { accessTokenLifeTime, refreshTokenLifeTime } from "../constants/auth.js";

const createSession = ()=> {
    const accessToken = randomBytes(30).toString("base64");
    const refreshToken = randomBytes(30).toString("base64");
    const accessTokenValidUntil = Date.now() + accessTokenLifeTime;
    const refreshTokenValidUnitl = Date.now() + refreshTokenLifeTime;

    return {
        accessToken,
        refreshToken,
        accessTokenValidUntil,
        refreshTokenValidUnitl,
    }
}

export const findSession = query => SessionCollection.findOne(query);

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
    const session = await findSession({refreshToken, _id: sessionId});
    if(!session) {
        throw createHttpError(401, "Session not found");
    }

    if(session.refreshTokenValidUnitl < Date.now()) {
        await SessionCollection.findOneAndDelete({_id: session._id});
        throw createHttpError(401, "Session token expired");
    }

    await SessionCollection.findOneAndDelete({_id: session._id});

    const newSession = createSession();

    return SessionCollection.create({
        userId: session.userId, 
        ...newSession,
    });
};

export const logoutUser = ({email}) => UserCollection.findOneAndUpdate({email}, {token: null});