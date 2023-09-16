/**
 * The `verifyToken` function is a middleware function in JavaScript that verifies a JWT token in the
 * request header and attaches the decoded user information to the request object.
 * @param req - The `req` parameter is the request object that contains information about the incoming
 * HTTP request, such as headers, query parameters, and request body. It is an object that is passed to
 * the middleware function by the Express framework.
 * @param res - The `res` parameter is the response object that is used to send the response back to
 * the client. It contains methods and properties that allow you to control the response, such as
 * setting the status code, sending JSON data, or redirecting the client to another URL.
 * @param next - The `next` parameter is a callback function that is used to pass control to the next
 * middleware function in the request-response cycle. It is typically called at the end of the current
 * middleware function to indicate that it has completed its processing and the next middleware
 * function should be called.
 * @returns If there is no token provided in the request header, the function will return a response
 * with status code 403 and the message "Access Denied". If the token starts with "Bearer ", it will
 * remove that prefix from the token. Then, it will verify the token using the JWT_SECRET from the
 * environment variables. If the token is successfully verified, the function will set the `req.user`
 * property to
 */
import jwt from "jsonwebtoken";

export const verifyToken = async (req, res, next) => {
    try {
        let token = req.header("Authorization");

        if (!token) {
            return res.status(403).send("Access Denied");
        }

        if (token.startsWith("Bearer ")) {
            token = token.slice(7, token.length).trimLeft();
        }

        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};