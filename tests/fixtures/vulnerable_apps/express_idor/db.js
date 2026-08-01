// Benign data-access stub — should triage clean.

const orders = new Map();

module.exports = {
  orders: {
    async findByPk(id) {
      return orders.get(String(id)) || null;
    },
    async put(id, record) {
      orders.set(String(id), record);
    },
  },
};
