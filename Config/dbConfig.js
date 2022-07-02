const mongoose = require("mongoose");
const path = require("path");
require("dotenv").config({
  path: path.resolve(__dirname, "../.env"),
});

exports.connectDB = async () => {
  return new Promise(async (resolve, reject) => {
    mongoose.connect(
      process.env.DB_URL,
      { useNewUrlParser: true, useUnifiedTopology: true },
      (err) => {
        if (err) reject(console.log(err));
      }
    );
    resolve(console.log("Connected to mongodb!"));
  });
};
