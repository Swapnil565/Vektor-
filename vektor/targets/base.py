from abc import ABC, abstractmethod
from typing import Optional, List, Dict


class BaseTarget(ABC):
    """
    Abstract base class for LLM provider adapters.

    State managed here:
    - request_count: total API calls made
    - total_cost: cumulative USD spent (used for delta tracking in attacks)
    - conversation_history: messages for stateful (multi-turn) queries
    - uploaded_documents: extracted document text for RAG simulation
    """

    def __init__(self, name: str):
        self.name = name
        self.request_count = 0
        self.total_cost = 0.0
        self.conversation_history: List[Dict] = []
        self.uploaded_documents: Dict[str, str] = {}

    @abstractmethod
    def query(self, prompt: str, stateful: bool = False, use_documents: bool = True, **kwargs) -> str:
        """
        Send a prompt to the LLM and return the response.

        Args:
            prompt: User message
            stateful: If True, include conversation_history in the request
            use_documents: If True, inject uploaded_documents into context
        """
        pass

    @abstractmethod
    def estimate_cost(self, prompt: str, response: Optional[str] = None) -> float:
        """Estimate cost of a query in USD."""
        pass

    @abstractmethod
    def get_refusal_patterns(self) -> List[str]:
        """
        Return provider-specific refusal patterns.

        These patterns are used by attacks to detect whether the model
        refused to execute a malicious instruction vs. actually executing it.

        Different providers have different refusal language:
        - OpenAI: "I cannot", "I'm unable to"
        - Anthropic: "I apologize, but I can't"
        - Local models: May vary by model

        Returns:
            List of lowercase refusal phrases
        """
        pass

    def supports_documents(self) -> bool:
        """Whether this target supports document upload simulation."""
        return False

    def upload_document(self, file_path: str) -> str:
        """Upload and extract a document for RAG simulation."""
        raise NotImplementedError(f"{self.name} does not support document upload")

    def clear_documents(self):
        """Clear all uploaded documents."""
        self.uploaded_documents.clear()

    def clear_conversation(self):
        """Clear conversation history (call between multi-turn test cases)."""
        self.conversation_history.clear()
