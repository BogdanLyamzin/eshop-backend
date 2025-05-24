import { registerUser, loginUser, refreshUser, logoutUser } from "../services/auth.js";

export const registerController = async(req, res)=> {
    await registerUser(req.body);

    res.status(201).json({
        status: 201,
        message: "Successfully register user",
    });
};

export const loginController = async(req, res)=> {
    const data = await loginUser(req.body);

    res.json({
        status: 200,
        message: "Login successfully",
        data
    });
};

export const getCurrentController = (req, res)=> {
    const {email} = req.user;

    res.json({
        email,
    });
}

export const refreshController = async(req, res)=> {
    await refreshUser(req.cookies);

    res.json({
        status: 200,
        message: "Session successfullt refresh",
        
    });
};

export const logoutController = async(req, res)=> {
    await logoutUser(req.user);

    res.status(204).send();
};
