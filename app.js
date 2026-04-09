require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const User = require('./user');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Post = require('./post');
const Joi = require('joi');
const schema = Joi.object({

    password: Joi.string().min(6).required(),

    email: Joi.string().email().required()
})

mongoose.connect("mongodb://localhost:27017/users")
    .then(() => { console.log("Connected to MongoDB Users") })
    .catch((err) => {console.log("Connection Failed!")})

const app = express();
app.use(express.json());

function checkAuth(req, res, next){
    const token = req.headers.authorization;
    if(!token){
        res.status(401).json({ error: "Unauthorized!" })
        return;
    }
    try{
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if(!decoded){
            res.status(401).json({ error: "Invalid token!" })
            return;
        }
        req.user = decoded;
        next();
    }catch(err){
        res.status(401).json({ error: "Invalid token!" });
        return;
    }
}

app.get("/", (req, res) => {
    res.send("Home");
});

app.get("/users", checkAuth, async (req, res, next) => {
    try{
        const users = await User.find().select('-password');
        res.json(users);
    } catch(err){
        next(err);
    }
});

app.post('/register', async (req, res, next) => {
    try{
        const result = schema.validate(req.body);
        if(result.error){
            res.status(400).json({ error: result.error.message});
            return;
        }
        const user = new User(req.body);
        const hashedPassword = await bcrypt.hash(user.password, 10);
        user.password = hashedPassword;
        await user.save();
        res.json({ message: "User saved!" });
    } catch(err){
        next(err);
    }
});

app.post('/login', async (req, res, next) => {
    try{
        const result = schema.validate(req.body);
        if(result.error){
            res.status(400).json({ error: result.error.message});
            return;
        }
        const { email, password } = req.body;
        const oldUser = await User.findOne({ email: email });
        if(!oldUser){
            res.status(404).json({ error: "User not found!" });
            return;
        }
        const isMatch = await bcrypt.compare(password, oldUser.password);
        if(!isMatch){
            res.status(401).json({ error: "Password does not match!" });
            return;
        }
        const token = jwt.sign({ _id: oldUser._id }, process.env.JWT_SECRET, { expiresIn: "1d" });
        res.json({ message: `User logged in your token is: ${token}` })
    } catch(err){
        next(err);
    }
});

app.delete('/user/:id', checkAuth, async (req, res, next) => {
    try{
        const result = schema.validate(req.body);
        if(result.error){
            res.status(400).json({ error: result.error.message});
            return;
        }
        const { email, password } = req.body;
        const oldUser = await User.findById(req.params.id);
        if(!oldUser){
            res.status(404).json({ error: "User not found!" });
            return;
        }
        const isMatch = await bcrypt.compare(password, oldUser.password);
        if(!isMatch){
            res.status(401).json({ error: "Password does not match!" });
            return;
        }
        await User.findByIdAndDelete(req.params.id)
        res.json({ message: `User deleted!` })
    } catch(err){
        next(err);
    }
});

app.post("/posts", checkAuth, async (req, res, next) => {
    try{
        if(!req.body.title || !req.body.content){
            res.status(400).json({ error: "Post data is required!" })
            return;
        }
        const post = new Post(req.body);
        post.author = req.user._id;
        await post.save();
        res.json({ message: "Post saved!" });
    } catch(err){
        next(err);
    }
})

app.get("/posts", checkAuth, async (req, res, next) => {
    try{
        const posts = await Post.find().populate('author');
        res.json(posts);
    } catch(err){
        next(err);
    }
});

app.use((err, req, res, next) => {
    res.status(500).json({ error: `An error occured while processing your request. Error: ${err.message}` });
})

app.listen(3000);
console.log("Listening on port 3000");
