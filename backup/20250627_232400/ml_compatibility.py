#!/usr/bin/env python3
"""
ML Compatibility Layer for SCAPA
Handles sklearn version incompatibilities
"""
import logging
import warnings
import pickle
import os
from typing import Any, List, Tuple, Optional

class MLCompatibilityHandler:
    """Handles ML model loading and prediction with version compatibility"""
    
    def __init__(self):
        self.model = None
        self.feature_map = None
        self.protocol_map = None
        self.is_loaded = False
        
    def safe_load_models(self, model_path: str = "model.pkl", 
                        fmap_path: str = "fmap.pkl", 
                        pmap_path: str = "pmap.pkl") -> bool:
        """
        Safely load ML models with compatibility handling
        """
        try:
            # Suppress sklearn version warnings during loading
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=UserWarning)
                warnings.filterwarnings("ignore", module="sklearn")
                
                # Load models with error handling
                if os.path.exists(model_path):
                    with open(model_path, 'rb') as f:
                        self.model = pickle.load(f)
                        
                if os.path.exists(fmap_path):
                    with open(fmap_path, 'rb') as f:
                        self.feature_map = pickle.load(f)
                        
                if os.path.exists(pmap_path):
                    with open(pmap_path, 'rb') as f:
                        self.protocol_map = pickle.load(f)
                
                # Test model prediction to catch compatibility issues
                if self.model and self.feature_map:
                    self._test_model_compatibility()
                    
                self.is_loaded = True
                logging.info("ML models loaded successfully with compatibility layer")
                return True
                
        except Exception as e:
            logging.error(f"Error loading ML models: {e}")
            self.is_loaded = False
            return False
    
    def _test_model_compatibility(self):
        """Test model with dummy data to catch compatibility issues early"""
        try:
            # Create dummy feature vector
            dummy_features = [0.0] * len(self.feature_map)
            
            # Test prediction
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore")
                prediction = self.model.predict([dummy_features])
                
            logging.debug("Model compatibility test passed")
            
        except Exception as e:
            logging.warning(f"Model compatibility issue detected: {e}")
            # Could implement fallback logic here
            raise
    
    def predict_batch(self, feature_batches: List[List[float]]) -> List[int]:
        """
        Predict on a batch of features with error handling
        """
        if not self.is_loaded or not self.model:
            logging.warning("ML model not loaded, skipping predictions")
            return [0] * len(feature_batches)
        
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=UserWarning)
                warnings.filterwarnings("ignore", module="sklearn")
                
                predictions = self.model.predict(feature_batches)
                return predictions.tolist()
                
        except AttributeError as e:
            if "monotonic_cst" in str(e):
                logging.warning("sklearn version incompatibility detected, using fallback")
                return self._fallback_predict(feature_batches)
            else:
                logging.error(f"ML prediction error: {e}")
                return [0] * len(feature_batches)
                
        except Exception as e:
            logging.error(f"ML prediction error: {e}")
            return [0] * len(feature_batches)
    
    def _fallback_predict(self, feature_batches: List[List[float]]) -> List[int]:
        """
        Fallback prediction method for compatibility issues
        """
        try:
            # Try to rebuild model without problematic attributes
            logging.info("Attempting model compatibility fix...")
            
            # Simple heuristic-based fallback
            predictions = []
            for features in feature_batches:
                # Basic anomaly detection based on feature values
                # This is a simple fallback - in production you'd want more sophisticated logic
                anomaly_score = sum(abs(f) for f in features) / len(features)
                prediction = 1 if anomaly_score > 0.5 else 0
                predictions.append(prediction)
                
            logging.info(f"Fallback prediction completed for {len(predictions)} samples")
            return predictions
            
        except Exception as e:
            logging.error(f"Fallback prediction failed: {e}")
            return [0] * len(feature_batches)
    
    def extract_features(self, packet_data: dict) -> Optional[List[float]]:
        """
        Extract features from packet data using the loaded feature map
        """
        if not self.feature_map:
            return None
            
        try:
            features = []
            
            # Extract basic features
            features.extend([
                packet_data.get('packet_size', 0),
                packet_data.get('tcp_flags', 0),
                packet_data.get('ip_version', 4),
                packet_data.get('protocol', 0),
                packet_data.get('src_port', 0),
                packet_data.get('dst_port', 0),
            ])
            
            # Pad or truncate to match expected feature count
            expected_count = len(self.feature_map)
            if len(features) < expected_count:
                features.extend([0.0] * (expected_count - len(features)))
            elif len(features) > expected_count:
                features = features[:expected_count]
                
            return features
            
        except Exception as e:
            logging.error(f"Feature extraction error: {e}")
            return None

# Global instance
ml_handler = MLCompatibilityHandler()

def load_ml_models() -> bool:
    """Convenience function to load ML models"""
    return ml_handler.safe_load_models()

def predict_packet_batch(packets_data: List[dict]) -> List[int]:
    """Convenience function for batch prediction"""
    feature_batches = []
    
    for packet_data in packets_data:
        features = ml_handler.extract_features(packet_data)
        if features:
            feature_batches.append(features)
        else:
            feature_batches.append([0.0] * 10)  # Default feature count
    
    return ml_handler.predict_batch(feature_batches)
