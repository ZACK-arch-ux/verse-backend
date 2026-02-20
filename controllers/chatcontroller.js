const Message = require("../models/Message");

// SEND MESSAGE
exports.sendMessage = async (req, res) => {
  try {
    const { receiver, text } = req.body;

    const message = await Message.create({
      sender: req.user.id,
      receiver,
      text
    });

    res.status(201).json(message);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// GET MESSAGES BETWEEN TWO USERS
exports.getMessages = async (req, res) => {
  try {
    const { userId } = req.params;

    const messages = await Message.find({
      $or: [
        { sender: req.user.id, receiver: userId },
        { sender: userId, receiver: req.user.id }
      ]
    }).sort({ createdAt: 1 });

    res.json(messages);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};