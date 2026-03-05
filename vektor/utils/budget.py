class BudgetManager:
    """Tracks and enforces API spending limits."""

    def __init__(self, limit: float = 1.0):
        self.limit = limit
        self.spent = 0.0

    def add_cost(self, cost: float):
        self.spent += cost

    def is_exceeded(self) -> bool:
        return self.spent >= self.limit

    def remaining(self) -> float:
        return max(0.0, self.limit - self.spent)

    def can_afford(self, estimated_cost: float) -> bool:
        return (self.spent + estimated_cost) <= self.limit

    def get_status(self) -> dict:
        return {
            "limit": self.limit,
            "spent": round(self.spent, 4),
            "remaining": round(self.remaining(), 4),
            "percentage_used": round((self.spent / self.limit * 100), 1) if self.limit > 0 else 0
        }
